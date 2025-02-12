{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.Root
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
-- Compute the root of a Merkle tree directly from the inputs.
--
module Data.MerkleLog.Root
( MerkleRoot
, merkleRootSize
, encodeMerkleRoot
, decodeMerkleRoot
, MerkleNodeType(..)
, merkleRoot
, merkleRootIO
, merkleRootStream

-- * Exceptions
, MerkleTreeException(..)

-- * Reference Implementation
, merkleRootSpec
) where

import Control.Monad
import Data.Bits
import Data.Hash.Class.Mutable
import Data.MerkleLog.Internal
import GHC.Stack
import Streaming.Prelude qualified as S
import System.IO.Unsafe

-- -------------------------------------------------------------------------- --
-- Root of a Merkle tree

-- | Compute the root of a Merkle tree from \(n\) input nodes in \(O(\log n)\)
-- space.
--
merkleRoot
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => [MerkleNodeType a]
    -> MerkleRoot a
merkleRoot = unsafeDupablePerformIO . merkleRootIO @a

-- | Compute the root of a Merkle tree from \(n\) input nodes in \(O(\log n)\)
-- space.
--
merkleRootIO
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => [MerkleNodeType a]
    -> IO (MerkleRoot a)
merkleRootIO l = do
    ctx <- initialize @a
    (_, s') <- foldM (step ctx) (0, []) l
    finalReduce ctx s'

-- | Compute the root of a Merkle tree from a stream of \(n\) input nodes in
-- space \(O(\log n)\).
--
merkleRootStream
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => S.Stream (S.Of (MerkleNodeType a)) IO ()
    -> IO (MerkleRoot a)
merkleRootStream l = do
    ctx <- initialize @a
    S.foldM_ (step ctx) (return (0, [])) (finalReduce ctx . snd) l

-- -------------------------------------------------------------------------- --
-- Implementation
--
-- The implementation reads a stream of leafs and simulates a parallel tree
-- contraction by storing intermediate results on a stack.

step
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => Context a
    -> (Int, [MerkleRoot a])
    -> MerkleNodeType a
    -> IO (Int, [MerkleRoot a])
step ctx (i,s) h = do
    !n <- merkleLeafIO ctx h
    !s' <- reduce ctx (countTrailingZeros (complement i)) (n:s)
    return (i+1, s')
{-# INLINE step #-}

reduce
    :: forall a
    . HasCallStack
    => MerkleHashAlgorithm a
    => Context a
    -> Int
    -> [MerkleRoot a]
    -> IO [MerkleRoot a]
reduce _ 0 s = return $! s
reduce ctx i (h0:h1:t) = do
    !n <- merkleNodeIO ctx h1 h0
    reduce ctx (i - 1) $ n : t
reduce _ _ s = error $ "Can not happen: stack length " <> show (length s)
{-# INLINE reduce #-}

finalReduce
    :: forall a
    . MerkleHashAlgorithm a
    => Context a
    -> [MerkleRoot a]
    -> IO (MerkleRoot a)
finalReduce _ [r] = return r
finalReduce ctx (h0:h1:t) = do
    !n <- merkleNodeIO ctx h1 h0
    finalReduce ctx $ n : t
finalReduce _ [] = return emptyTreeRoot
{-# INLINE finalReduce #-}

emptyTreeRoot :: forall a . MerkleHashAlgorithm a => MerkleRoot a
emptyTreeRoot = MerkleRoot (nullHashBytes @a)
{-# INLINE emptyTreeRoot #-}

-- -------------------------------------------------------------------------- --
-- Reference Implementation

-- | This is the reference implementation. It is not intended for production
-- use. It less efficient than the optimized implementations that are provided
-- in this module.
--
merkleRootSpec
    :: forall a
    . Hash a
    => MerkleHashAlgorithm a
    => [MerkleNodeType a]
    -> MerkleRoot a
merkleRootSpec l = go 0 l []
  where
    go :: Int -> [MerkleNodeType a] -> [MerkleRoot a] -> MerkleRoot a
    go _ [] s = finalPop s
    go i (h:t) s = go (i + 1) t $!
        pop (countTrailingZeros (complement i)) $ (:s) $! merkleLeaf h

    pop :: Int -> [MerkleRoot a] -> [MerkleRoot a]
    pop 0 s = s
    pop i (h0:h1:t) = pop (i - 1) $ (:t) $! merkleNode h1 h0
    pop _ _ = error "Can not happen"

    finalPop :: [MerkleRoot a] -> MerkleRoot a
    finalPop [r] = r
    finalPop (h0:h1:t) = finalPop $ (:t) $! merkleNode h1 h0
    finalPop [] = emptyTreeRoot

