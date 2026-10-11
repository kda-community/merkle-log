-- |
-- Module: Data.MerkleLog.Common
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.Common
(
-- * Exceptions
  Expected(..)
, Actual(..)
, MerkleTreeException(..)
, textMessage

-- * Merkle Hash Algorithm
, MerkleHashAlgorithm(..)

-- * Merkle Tree Nodes
, MerkleNodeType(..)
, merkleLeaf
, merkleNode

-- * Merkle Root
, MerkleRoot
, merkleRootBytes
, merkleRootSize
, encodeMerkleRoot
, decodeMerkleRoot
) where


import Data.MerkleLog.Internal
