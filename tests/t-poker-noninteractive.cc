/*******************************************************************************
   This file is part of LibTMCG.

 Copyright (C) 2016, 2017, 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

   LibTMCG is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   LibTMCG is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with LibTMCG; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

// include headers
#ifdef HAVE_CONFIG_H
	#include "libTMCG_config.h"
#endif
#include <libTMCG.hh>

#include <exception>
#include <sstream>
#include <vector>
#include <cassert>

#include "test_helper.h"

#undef NDEBUG
#define PLAYERS 2
#define DECKSIZE 52
#define FLOP_CARDS 3
#define TURN_CARDS 1
#define RIVER_CARDS 1

struct PlayerCtx
{
	size_t id;
	SchindelhauerTMCG *tmcg;
	BarnettSmartVTMF_dlog *vtmf;
	GrothVSSHE *vsshe;
};

static void open_card_for_player
	(PlayerCtx &owner, const std::vector<PlayerCtx> &others, VTMF_Card &card,
	 size_t &out_type)
{
	owner.tmcg->TMCG_SelfCardSecret(card, owner.vtmf);
	for (const auto &p : others)
	{
		if (p.id == owner.id)
			continue;
		std::istringstream dummy_in("");
		std::stringstream proof;
		p.tmcg->TMCG_ProveCardSecret(card, p.vtmf, dummy_in, proof);
		std::istringstream proof_in(proof.str());
		std::ostringstream dummy_out;
		if (!owner.tmcg->TMCG_VerifyCardSecret(card, owner.vtmf, proof_in,
			dummy_out))
		{
			throw std::runtime_error("Card verification failed");
		}
	}
	out_type = owner.tmcg->TMCG_TypeOfCard(card, owner.vtmf);
}

static void open_public_cards
	(PlayerCtx &opener, const std::vector<PlayerCtx> &players,
	 TMCG_Stack<VTMF_Card> &encrypted_cards, size_t count,
	 TMCG_OpenStack<VTMF_Card> &open_out)
{
	for (size_t i = 0; i < count; i++)
	{
		VTMF_Card c;
		encrypted_cards.pop(c);
		size_t type = 0;
		open_card_for_player(opener, players, c, type);
		open_out.push(type, c);
	}
}

int main
	(int argc, char **argv)
{
	assert(((argc > 0) && (argv != NULL)));
	assert(init_libTMCG());

	try
	{
		// Common VTMF group setup.
		std::cout << "BarnettSmartVTMF_dlog()" << std::endl;
		BarnettSmartVTMF_dlog *group_vtmf = new BarnettSmartVTMF_dlog();
		std::cout << "vtmf.CheckGroup()" << std::endl;
		start_clock();
		assert(group_vtmf->CheckGroup());
		stop_clock();
		std::cout << elapsed_time() << std::endl;

		std::stringstream vtmf_str;
		std::cout << "vtmf.PublishGroup(vtmf_str)" << std::endl;
		group_vtmf->PublishGroup(vtmf_str);

		// Create player contexts (single-process, ordered simulation).
		std::vector<PlayerCtx> players;
		players.reserve(PLAYERS);
		for (size_t i = 0; i < PLAYERS; i++)
		{
			start_clock();
			SchindelhauerTMCG *tmcg = new SchindelhauerTMCG(64, PLAYERS, 6);
			std::stringstream vtmf_copy(vtmf_str.str());
			BarnettSmartVTMF_dlog *vtmf = new BarnettSmartVTMF_dlog(vtmf_copy);
			if (!vtmf->CheckGroup())
				throw std::runtime_error("Group G was not correctly generated");
			stop_clock();
			std::cout << "P_" << i << ": " << elapsed_time() << std::endl;
			players.push_back({i, tmcg, vtmf, NULL});
		}

		// Key generation protocol in proper order.
		std::cout << "=== Key Generation ===" << std::endl;
		start_clock();
		for (auto &p : players)
			p.vtmf->KeyGenerationProtocol_GenerateKey();
		for (size_t i = 0; i < PLAYERS; i++)
		{
			for (size_t j = 0; j < PLAYERS; j++)
			{
				if (i == j)
					continue;
				std::stringstream msg;
				players[i].vtmf->KeyGenerationProtocol_PublishKey(msg);
				std::stringstream msg_in(msg.str());
				if (!players[j].vtmf->KeyGenerationProtocol_UpdateKey(msg_in))
					throw std::runtime_error("Public key update failed");
			}
		}
		for (auto &p : players)
			p.vtmf->KeyGenerationProtocol_Finalize();
		stop_clock();
		std::cout << "keys: " << elapsed_time() << std::endl;

		// VSSHE setup (player 0 is leader).
		std::cout << "=== VSSHE Setup ===" << std::endl;
		start_clock();
		players[0].vsshe = new GrothVSSHE(DECKSIZE,
			players[0].vtmf->p, players[0].vtmf->q, players[0].vtmf->k,
			players[0].vtmf->g, players[0].vtmf->h);
		if (!players[0].vsshe->CheckGroup())
			throw std::runtime_error("VSSHE leader group check failed");
		std::stringstream vsshe_group;
		players[0].vsshe->PublishGroup(vsshe_group);
		for (size_t i = 1; i < PLAYERS; i++)
		{
			std::stringstream vsshe_in(vsshe_group.str());
			players[i].vsshe = new GrothVSSHE(DECKSIZE, vsshe_in);
			if (!players[i].vsshe->CheckGroup())
				throw std::runtime_error("VSSHE non-leader group check failed");
			if (mpz_cmp(players[i].vtmf->h, players[i].vsshe->com->h) ||
				mpz_cmp(players[i].vtmf->q, players[i].vsshe->com->q))
			{
				throw std::runtime_error("VSSHE common key mismatch");
			}
		}
		stop_clock();
		std::cout << "vsshe: " << elapsed_time() << std::endl;

		// Create initial public deck and encrypted stack.
		std::cout << "=== Deck Creation ===" << std::endl;
		start_clock();
		TMCG_OpenStack<VTMF_Card> deck_open;
		for (size_t type = 0; type < DECKSIZE; type++)
		{
			VTMF_Card c;
			players[0].tmcg->TMCG_CreateOpenCard(c, players[0].vtmf, type);
			deck_open.push(type, c);
		}
		TMCG_Stack<VTMF_Card> s_current;
		s_current.push(deck_open);
		stop_clock();
		std::cout << "deck: " << elapsed_time() << std::endl;

		// Sequential shuffling with proofs.
		std::cout << "=== Shuffling ===" << std::endl;
		for (size_t shuffler = 0; shuffler < PLAYERS; shuffler++)
		{
			std::cout << "P_" << shuffler << " shuffles" << std::endl;
			start_clock();
			TMCG_Stack<VTMF_Card> s_next;
			TMCG_StackSecret<VTMF_CardSecret> ss;
			std::stringstream proof;
			players[shuffler].tmcg->TMCG_CreateStackSecret(ss, false,
				s_current.size(), players[shuffler].vtmf);
			players[shuffler].tmcg->TMCG_MixStack(s_current, s_next, ss,
				players[shuffler].vtmf);
			players[shuffler].tmcg->TMCG_ProveStackEquality_Groth_noninteractive(
				s_current, s_next, ss, players[shuffler].vtmf,
				players[shuffler].vsshe, proof);

			for (size_t verifier = 0; verifier < PLAYERS; verifier++)
			{
				if (verifier == shuffler)
					continue;
				std::stringstream proof_in(proof.str());
				if (!players[verifier].tmcg->
					TMCG_VerifyStackEquality_Groth_noninteractive(
						s_current, s_next, players[verifier].vtmf,
						players[verifier].vsshe, proof_in))
				{
					throw std::runtime_error("Shuffle verification failed");
				}
			}
			s_current = s_next;
			stop_clock();
			std::cout << "shuffle time: " << elapsed_time() << std::endl;
		}

		// Deal hole cards (preflop).
		std::cout << "=== Preflop ===" << std::endl;
		start_clock();
		TMCG_Stack<VTMF_Card> hand_enc[PLAYERS];
		for (size_t i = 0; i < PLAYERS; i++)
		{
			VTMF_Card c1, c2;
			s_current.pop(c1);
			s_current.pop(c2);
			hand_enc[i].push(c1);
			hand_enc[i].push(c2);
		}

		for (size_t i = 0; i < PLAYERS; i++)
		{
			TMCG_OpenStack<VTMF_Card> private_hand;
			for (size_t k = 0; k < hand_enc[i].size(); k++)
			{
				size_t type = 0;
				open_card_for_player(players[i], players, hand_enc[i][k], type);
				private_hand.push(type, hand_enc[i][k]);
			}
			std::cout << "P_" << i << ": my cards are "
				<< private_hand[0].first << " and "
				<< private_hand[1].first << std::endl;
		}
		stop_clock();
		std::cout << "preflop open: " << elapsed_time() << std::endl;

		// Reveal community cards in order: flop, turn, river.
		TMCG_OpenStack<VTMF_Card> community_open;

		std::cout << "=== Flop ===" << std::endl;
		start_clock();
		open_public_cards(players[0], players, s_current, FLOP_CARDS,
			community_open);
		stop_clock();
		std::cout << "flop open: " << elapsed_time() << std::endl;
		std::cout << "flop cards are ";
		for (size_t i = 0; i < FLOP_CARDS; i++)
			std::cout << community_open[i].first << " ";
		std::cout << std::endl;

		std::cout << "=== Turn ===" << std::endl;
		start_clock();
		open_public_cards(players[0], players, s_current, TURN_CARDS,
			community_open);
		stop_clock();
		std::cout << "turn open: " << elapsed_time() << std::endl;
		std::cout << "turn card is " << community_open[FLOP_CARDS].first
			<< std::endl;

		std::cout << "=== River ===" << std::endl;
		start_clock();
		open_public_cards(players[0], players, s_current, RIVER_CARDS,
			community_open);
		stop_clock();
		std::cout << "river open: " << elapsed_time() << std::endl;
		std::cout << "river card is "
			<< community_open[FLOP_CARDS + TURN_CARDS].first << std::endl;

		// release instances
		for (auto &p : players)
		{
			delete p.tmcg;
			delete p.vtmf;
			delete p.vsshe;
		}
		delete group_vtmf;

		return 0;
	}
	catch (std::exception& e)
	{
		std::cerr << "exception catched with what = " << e.what() << std::endl;
		return -1;
	}
}
