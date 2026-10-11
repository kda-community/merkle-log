-- |
-- Module: Data.MerkleLog.V1
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.V1
(
-- * Merkle Hash Algorithm
  MerkleHashAlgorithm(..)

-- * Merkle Tree
, MerkleTree
, decodeMerkleTree
, emptyMerkleTree
, encodeMerkleTree
, isEmpty
, leafCount
, merkleTree
, merkleTreeProof
, merkleTreeProof_
, merkleTreeRoot
, size

-- * Merkle Root
, MerkleRoot
, merkleRootSize
, encodeMerkleRoot
, decodeMerkleRoot
, merkleRoot

-- * Merkle Proofs V1
, MerkleProof(..)
, MerkleProofSubject(..)
, MerkleProofObject(..)
, encodeMerkleProofObject
, decodeMerkleProofObject
, runMerkleProof
) where

import Data.MerkleLog.Common
import Data.MerkleLog.Root
import Data.MerkleLog.V1.Proof
import Data.MerkleLog.V1.Tree
