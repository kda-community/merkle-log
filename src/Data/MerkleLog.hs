{-# LANGUAGE ExplicitNamespaces #-}

-- |
-- Module: Data.MerkleLog
-- Copyright: Copyright © 2019 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- NOTE: this module provides the V2 proof format which is not backward
-- compatible with the older V1 format provided in "Data.MerkleLog.Tree". This
-- module also provides more efficient direct computations for the root and
-- proofs that don't construct the full Merkle tree in memory. If caching of the
-- full tree is needed the old version must be used. But this should almost
-- never be the case.
--
-- Merkle Logs are an append-only data structure. The tree layout in this
-- implementation of Merkle trees is based on the description of Merkle trees in
-- RFC 6962. With this tree layout extending a Merkle tree requires chaining a
-- logarithmic number of nodes at the end of the tree. Unlike RFC 6962 the
-- Merkle trees in this module support the creation of unbalanced MerkleTrees by
-- nesting sub-trees as leafs of Merkle trees. Also, unlike RFC 6962 this module
-- generates fully self-contained inclusion proofs that don't rely on the client
-- being aware of the balancing of the Merkle Tree that was used to generate the
-- proof.
--
-- = Example
--
-- @
-- {-\# LANGUAGE TypeApplications #-}
-- {-\# LANGUAGE OverloadedStrings #-}
--
-- import qualified Data.ByteString as B
-- import Data.Hash.SHA2 (Sha2_256)
--
-- inputs = InputNode <$> ["a", "b", "c"] :: [MerkleNodeType Sha2_256]
--
-- -- create inclusion proof
-- p = either (error . show) id $ merkleProof 1 inputs
--
-- -- verify proof
-- runMerkleProof p == merkleRoot inputs
-- @
--
-- = TODO
--
-- * implement consistency proofs
-- * documentation for encodings and algorithms
--
module Data.MerkleLog
(
-- * Exceptions
  Expected(..)
, Actual(..)
, MerkleTreeException(..)

-- * Merkle Hash Algorithm
, MerkleHashAlgorithm(..)

-- * Merkle Tree Nodes
, MerkleNodeType(..)

-- * Merkle Root
, MerkleRoot
, merkleRoot
, merkleRootIO
, merkleRootStream
, merkleRootBytes
, merkleRootSize
, encodeMerkleRoot
, decodeMerkleRoot

-- * Merkle Proofs V2
, MerkleProof(..)
, merkleProof
, merkleProofIO
, merkleProofStream
, runProof
, runProofIO
, composeProofs
, concatProofs
, encodeProof
, decodeProof
) where

import Data.MerkleLog.Common
import Data.MerkleLog.Proof
import Data.MerkleLog.Root
