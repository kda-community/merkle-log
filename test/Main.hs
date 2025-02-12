{-# LANGUAGE CPP #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

{-# OPTIONS_GHC -fno-warn-orphans #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE ConstraintKinds #-}

-- |
-- Module: Main
-- Copyright: Copyright © 2019 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Main
( main
) where

import Control.DeepSeq
import Control.Monad.Catch
import Data.Bits hiding ((.&.))
import Data.ByteString qualified as B
import Data.ByteString.Char8 qualified as B8
import Data.ByteString.Short qualified as BS
import Data.Coerce
import Data.Hash.SHA2
import Data.List.NonEmpty qualified as NE
import Data.Maybe
import Data.MerkleLog
import Data.MerkleLog.Internal qualified as MLI
import Data.MerkleLog.V1 qualified as V1
import Data.Word
import GHC.Num
import Test.Hspec
import Test.Hspec.QuickCheck
import Test.QuickCheck
import Data.MerkleLog.Utils

-- -------------------------------------------------------------------------- --
-- Main

type H = Sha2_512_256

main :: IO ()
main = hspec spec

spec :: Spec
-- spec = parallel $ do
spec = do
    describe "QuickCheck Properties for V2 proofs" $ do
        prop "create and verify merkle proof v2" $ property prop_proofV2
        prop "create and verify merkle proof v2 for all tree items for tree of size 30" $ prop_proofExhaustiveV2 30
        prop "create and verify merkle proof v2 for tree of size 1000 with items of sizes up to 1000 bytes" $ prop_proofSizeV2 1000 1000
        prop "creating proof v2 for invalid input pos fails" $ property prop_proofInvalidInputPosV2
        prop "running proof v2 with invalid claim fails" $ property prop_proofInvalidClaimV2
        prop "running proof v2 with invalid trace fails" $ property prop_proofInvalidTraceV2
        prop "running proof v2 with invalid step count fails" $ property prop_proofInvalidStepCountV2
        prop "running proof v2 with invalid evidence hash fails" $ property prop_proofInvalidEvidenceHashV2
        prop "create and verify merkle proof v2 for nested trees" $ property prop_chainProofV2
        prop "encoding roundtrip for merkle proof v2" $ property prop_encodeProofV2
        proofV2Serialization
        proofV2Tests
    specV1

specV1 :: Spec
specV1 = describe "V1" $ do
    describe "QuickCheck Properties for Tree and V1 proofs" $ do
        prop "create merkle tree and confirm the size" $ property prop_treeV1
        prop "create and verify merkle proof" $ property prop_proofV1
        prop "create and verify merkle proof for all tree items for tree of size 30" $ prop_proofExhaustiveV1 30
        prop "create and verify merkle proof for tree of size 1000 with items of sizes up to 1000 bytes" $ prop_proofSizeV1 1000 1000
        prop "creating proof for invalid input fails" $ property prop_proofInvalidInputV1
        prop "running proof with invalid subject fails" $ property prop_proofInvalidSubjectV1
        prop "running proof with invalid object path fails" $ property prop_proofInvalidObjectPathV1
        prop "running proof with invalid object hash fails" $ property prop_proofInvalidObjectHashV1
        prop "running proof with invalid object step count fails" $ property prop_proofInvalidStepCountV1
        prop "create and verify merkle proof for nested trees" $ property prop_chainProofV1
        prop "encoding roundtrip for merkle proof object" $ property prop_encodeProofObjectV1
        prop "encoding roundtrip for merkle proof chain object" $ property prop_encodeProofChainObjectV1
        prop "encoding roundtrip for merkle root" $ property prop_encodeMerkleRoot
        prop "encoding roundtrip for merkle tree" $ property prop_encodeMerkleTreeV1

-- -------------------------------------------------------------------------- --
-- Utils

unpackBytes :: Coercible BS.ShortByteString a => a -> [Word8]
unpackBytes = BS.unpack . coerce

packBytes :: Coercible BS.ShortByteString a => [Word8] -> a
packBytes = coerce . BS.pack

nodeCount :: Int -> Int
nodeCount i = max 1 (2 * i - 1)
{-# INLINE nodeCount #-}

-- | Change diretion of first proof step. Throws error is the proof
-- is empty (singleton tree).
--
changeProofPathV1 :: MerkleHashAlgorithm a => V1.MerkleProof a -> V1.MerkleProof a
changeProofPathV1 p = p { V1._merkleProofObject = obj }
  where
    obj = case V1.decodeMerkleProofObject (B.pack o) of
        Right x -> x
        Left e -> error $ "test/Main.chainProofPath: failed to decode proof object: " <> show e
    o = case splitAt 12 (unpackBytes (V1._merkleProofObject p)) of
        (h, 0x00 : t) -> h <> (0x01 : t)
        (h, 0x01 : t) -> h <> (0x00 : t)
        (_, _ : _) -> error "invalid proof object"
        (_, []) -> error "unexpected empty proof object"

-- | Change diretion of first proof step. Throws error is the proof
-- is empty (singleton tree).
--
changeProofTraceV2 :: MerkleHashAlgorithm a => MerkleProof a -> MerkleProof a
changeProofTraceV2 p = p { _merkleProofTrace = _merkleProofTrace p .^. 0x1 }

-- | Change hash of first proof step. Throws error is the proof
-- is empty (singleton tree).
--
changeProofHashV1 :: MerkleHashAlgorithm a => V1.MerkleProof a -> V1.MerkleProof a
changeProofHashV1 p = p { V1._merkleProofObject = obj }
  where
    obj = case V1.decodeMerkleProofObject (B.pack o) of
        Right x -> x
        Left e -> error $ "test/Main.chainProofHash: failed to decode proof object: " <> show e
    o = case splitAt 12 (unpackBytes (V1._merkleProofObject p)) of
        (h, h1 : h2 : t) -> h <> (h1 : 1 + h2 : t)
        (_, []) -> error "unexpected empty proof object"
        _ -> error "invalid proof object"

-- | Change hash of first proof step. Throws error is the proof
-- is empty (singleton tree).
--
changeProofHashV2 :: MerkleHashAlgorithm a => MerkleProof a -> MerkleProof a
changeProofHashV2 MerkleProof { _merkleProofEvidence = [] } =
    error "changeProofHash: can't tamper with empty proof evidence"
changeProofHashV2 p@(MerkleProof { _merkleProofEvidence = (x:y) }) =
    p { _merkleProofEvidence = x' : y  }
  where
    x' = case splitAt 12 (unpackBytes $ merkleRootBytes x) of
        (h, h1 : h2 : t) -> packBytes $ h <> (h1 : 1 + h2 : t)
        (_, []) -> error "unexpected empty proof hash"
        _ -> error "invalid proof object"

-- | Changes the proof step count and verifies that decoding of the modified proof object fails.
-- Throws error is the proof is empty (singleton tree).
--
changeProofStepCountV1 :: forall a . MerkleHashAlgorithm a => V1.MerkleProof a -> Bool
changeProofStepCountV1 p = case r of
    Left _ -> True
    Right _ -> False
  where
    r = V1.decodeMerkleProofObject @a . B.pack
        $ case splitAt 3 (unpackBytes (V1._merkleProofObject p)) of
            (h, c : t) -> h <> (c + 1 : t)
            (_, []) -> error "unexpected empty proof object"

-- -------------------------------------------------------------------------- --
-- Generators

newtype UniqueInputs a = UniqueInputs [MerkleNodeType a]
    deriving Show

instance MerkleHashAlgorithm a => Arbitrary (UniqueInputs a) where
    arbitrary = UniqueInputs
        . zipWith (\a () -> InputNode $ B8.pack (show a)) [0 :: Int .. ]
        <$> arbitrary

instance MerkleHashAlgorithm a => Arbitrary (MerkleNodeType a) where
    arbitrary = oneof
        [ InputNode . B.pack <$> arbitrary
        , TreeNode <$> arbitrary
        ]

instance MerkleHashAlgorithm a => Arbitrary (MerkleRoot a) where
    arbitrary = MLI.merkleLeaf <$> arbitrary

instance MerkleHashAlgorithm a => Arbitrary (V1.MerkleTree a) where
    arbitrary = V1.merkleTree <$> arbitrary @[MerkleNodeType a]

instance MerkleHashAlgorithm a => Arbitrary (V1.MerkleProof a) where
    arbitrary = go `suchThatMap` either (const Nothing) Just
      where
        go = do
            NonEmpty l <- arbitrary @(NonEmptyList (MerkleNodeType a))
            i <- choose (0, length l - 1)
            return (V1.merkleTreeProof (l !! i) i (V1.merkleTree l))

instance MerkleHashAlgorithm a => Arbitrary (MerkleProof a) where
    arbitrary = go `suchThatMap` either (const Nothing) Just
      where
        go = do
            NonEmpty l <- arbitrary @(NonEmptyList (MerkleNodeType a))
            i <- choose (0, length l - 1)
            return (merkleProof i l)

-- -------------------------------------------------------------------------- --
-- Merkle Tree Chains for V1 proofs

-- | A chain of nested Merkle trees.
--
newtype MerkleTreeChain a = MerkleTreeChain
    { _getMerkleTreeChain :: NE.NonEmpty (Int, V1.MerkleTree a)
        -- ^ a list of of merkle trees along with the position of the previous
        -- tree in the chain
    }
    deriving Show

genTrees
    :: forall a
    . MerkleHashAlgorithm a
    => Gen (MerkleTreeChain a)
genTrees = do
    a <- genTree (InputNode "a")
    i <- choose @Int (0, 10)
    MerkleTreeChain . (NE.:|) a <$> go i (V1.merkleTreeRoot $ snd a)
  where
    genTree x = do
        il <- arbitrary @[MerkleNodeType a]
        ir <- arbitrary
        return (length il , V1.merkleTree (concat [il, pure x, ir]))

    go 0 _ = return []
    go i r = do
        a <- genTree (TreeNode r)
        (:) a <$> go (pred i) (V1.merkleTreeRoot $ snd a)

instance MerkleHashAlgorithm a => Arbitrary (MerkleTreeChain a) where
    arbitrary = genTrees

-- -------------------------------------------------------------------------- --
-- Test Tree for V2 Proofs

data TreeV2 a
    = TreeEmpty
    | TreeCons BS.ShortByteString (TreeV2 a)
    | TreeNest (TreeV2 a) (TreeV2 a)
    deriving (Show, Eq)

_treeV2Depth :: TreeV2 a -> Natural
_treeV2Depth TreeEmpty = 0
_treeV2Depth (TreeCons _ t) = _treeV2Depth t
_treeV2Depth (TreeNest h t) = max (1 + _treeV2Depth h) (_treeV2Depth t)

treeV2LeafCount :: TreeV2 a -> Natural
treeV2LeafCount TreeEmpty = 0
treeV2LeafCount (TreeCons _ t) = 1 + treeV2LeafCount t
treeV2LeafCount (TreeNest h t) = treeV2LeafCount h + treeV2LeafCount t

treeV2Root :: forall a . MerkleHashAlgorithm a => TreeV2 a -> MerkleRoot a
treeV2Root = merkleRoot @a . leafs @a

leafs :: forall a . MerkleHashAlgorithm a => TreeV2 a -> [MerkleNodeType a]
leafs TreeEmpty = []
leafs (TreeCons h t) = InputNode (BS.fromShort h) : leafs t
leafs (TreeNest h t) = TreeNode (merkleRoot @a (leafs h)) : leafs t

-- | Create a list of linearly nested subtree, represented by the leafs of each
-- tree and the position where respective subtree is nested.
--
-- The order of sub trees is top-down, starting at the root tree.
--
subTree
    :: forall a
    . MerkleHashAlgorithm a
    => Natural
    -> TreeV2 a
    -> NE.NonEmpty (Int,[MerkleNodeType a])
subTree a b = case check <$> go (fromIntegral a) b 0 of
    (h:t) -> h NE.:| t
    _ -> error "something went wrong: empty subtree proof"
  where
    check e@(Nothing, _) = error $ "invalid subtree position: " <> show e
        <> ", pos: " <> show a
        <> ", leafCount " <> show (treeV2LeafCount b)
    check (Just x, y) = (x, y)

    go :: Int -> (TreeV2 a) -> Int -> [(Maybe Int, [MerkleNodeType a])]
    go _ TreeEmpty _ = [(Nothing, [])]

    go 0 (TreeCons h t) c = case go (-1) t (c + 1) of
        [(Nothing, r)] -> [(Just c, InputNode (BS.fromShort h) : r)]
        e -> error $ "cannot happen (0): " <> show e
    go i (TreeCons h t) c = case go (i-1) t (c + 1) of
        (x, r) : tt -> (x, InputNode (BS.fromShort h) : r) : tt
        e -> error $ "cannot happen (1): " <> show e

    go i (TreeNest n t) c = case go i n 0 of
        -- FXIME don't traverse the subtree twice!
        [(Nothing, l)] -> case go (i - fromIntegral (treeV2LeafCount n)) t (c + 1) of
            (x, r) : tt -> (x, TreeNode (merkleRoot @a l) : r) : tt
            e -> error $ "cannot happen (2): " <> show e

        -- at this point we don't care about the value of "i" as long as it
        -- remains negative, so we can just start with (-1).
        (Just d, l) : tt -> case go (-1) t (c + 1) of
            [(Nothing, r)] -> (Just c, TreeNode (merkleRoot @a l) : r) : (Just d, l) : tt
            e -> error $ "cannot happen (4): " <> show e
        e -> error $ "cannot happen (5): " <> show e

-- Note that we don't allow empty subtrees, because we can't generate proofs for
-- those. (we don't have a notion of empty claim.)
--
genTreeV2
    :: forall a
    . MerkleHashAlgorithm a
    => Gen (TreeV2 a)
genTreeV2 = do
    sd <- fromIntegral . min 10 . max 0 . integerLog2 . fromIntegral <$> getSize
    d <- choose @Int (0, sd)
    go d
  where
    go d = do
        sn <- getSize
        n <- choose @Int (1, min 10 (sn + 1))
        go2 d n

    go2 _ 0 = pure TreeEmpty
    go2 0 i = TreeCons <$> (BS.pack <$> arbitrary) <*> go2 0 (i - 1)
    go2 d i = oneof
        [ TreeCons <$> (BS.pack <$> arbitrary) <*> go2 d (i - 1)
        , TreeNest <$> go (d - 1) <*> go2 d (i - 1)
        ]

instance MerkleHashAlgorithm a => Arbitrary (TreeV2 a) where
    arbitrary = genTreeV2

-- -------------------------------------------------------------------------- --
-- Properties

prop_treeV1 :: [MerkleNodeType H] -> Property
prop_treeV1 l = V1.size t === nodeCount (length l) .&. V1.leafCount t === length l
  where
    t = force $ V1.merkleTree @H l

prop_proofV1 :: [MerkleNodeType H] -> NonNegative Int -> Property
prop_proofV1 l (NonNegative i) = i < length l ==> V1.runMerkleProof p === Just (V1.merkleTreeRoot t)
  where
    t = V1.merkleTree @H l
    p = case V1.merkleTreeProof (l !! i) i t of
        Left e -> error (displayException e)
        Right x -> x

prop_proofV2 :: [MerkleNodeType H] -> NonNegative Int -> Property
prop_proofV2 l (NonNegative i) = i < length l ==>
    runProof p === Just (merkleRoot l)
  where
    p = case merkleProof i l of
        Left e -> error (displayException e)
        Right x -> x

-- | Runtime is quadradic in the input parameter. 50 ~ 1sec, 100 ~ 5sec.
--
prop_proofExhaustiveV1 :: Int -> Property
prop_proofExhaustiveV1 n = once $ conjoin
    [ prop_proofV1 ((InputNode . B.singleton . fromIntegral) <$> [0 .. i]) (NonNegative j)
    | i <- [0..n]
    , j <- [0..i]
    ]

prop_proofExhaustiveV2 :: Int -> Property
prop_proofExhaustiveV2 n = once $ conjoin
    [ prop_proofV2 ((InputNode . B.singleton . fromIntegral) <$> [0 .. i]) (NonNegative j)
    | i <- [0..n]
    , j <- [0..i]
    ]

-- | Runtime of @testSize n m@ can be expected to be bounded by @Ω(n * m)@.
-- @testSize 1000 1000@ ~ 1sec.
--
prop_proofSizeV1 :: Int -> Int -> Property
prop_proofSizeV1 n m = once $ do
    l <- vectorOf n (resize m arbitrary)
    i <- choose (0, n - 1)
    return $ prop_proofV1 l (NonNegative i)

prop_proofSizeV2 :: Int -> Int -> Property
prop_proofSizeV2 n m = once $ do
    l <- vectorOf n (resize m arbitrary)
    i <- choose (0, n - 1)
    return $ prop_proofV2 l (NonNegative i)

prop_proofInvalidInputV1
    :: [MerkleNodeType H]
    -> NonNegative Int
    -> Property
prop_proofInvalidInputV1 a (NonNegative i) = i < length a && notElem (InputNode "a") a
    ==> case V1.merkleTreeProof (InputNode "a") i (V1.merkleTree @H a) of
        Left _ -> True
        Right _ -> False

prop_proofInvalidInputPosV2
    :: [MerkleNodeType H]
    -> NonNegative Int
    -> Property
prop_proofInvalidInputPosV2 a (NonNegative i) = i < length a && notElem (InputNode "a") a
    ==> case merkleProof (length a + 1) a of
        Left _ -> True
        Right _ -> False

prop_proofInvalidSubjectV1
    :: [MerkleNodeType H]
    -> NonNegative Int
    -> Property
prop_proofInvalidSubjectV1 l (NonNegative i) = i < length l
    ==> V1.runMerkleProof p' =/= Just (V1.merkleTreeRoot t)
  where
    t = V1.merkleTree @H l
    p = case V1.merkleTreeProof (l !! i) i t of
        Left e -> error (displayException e)
        Right x -> x
    p' = p { V1._merkleProofSubject = changeSubject (V1._merkleProofSubject p) }
    changeSubject (V1.MerkleProofSubject (InputNode "a")) = V1.MerkleProofSubject (InputNode "b")
    changeSubject _ = V1.MerkleProofSubject (InputNode "a")

prop_proofInvalidClaimV2
    :: [MerkleNodeType H]
    -> NonNegative Int
    -> Property
prop_proofInvalidClaimV2 l (NonNegative i) = i < length l
    ==> runProof p' =/= Just (merkleRoot l)
  where
    p = case merkleProof i l of
        Left e -> error (displayException e)
        Right x -> x
    p' = p { _merkleProofClaim = changeClaim (_merkleProofClaim p) }
    changeClaim (InputNode "a") = InputNode "b"
    changeClaim _ = InputNode "a"

prop_proofInvalidObjectPathV1
    :: UniqueInputs H
    -> NonNegative Int
    -> Property
prop_proofInvalidObjectPathV1 (UniqueInputs l) (NonNegative i)
    = length l > 1 && i < length l
    ==> V1.runMerkleProof (changeProofPathV1 p) =/= Just (V1.merkleTreeRoot t)
  where
    t = V1.merkleTree @H l
    p = case V1.merkleTreeProof (l !! i) i t of
        Left e -> error (displayException e)
        Right x -> x

prop_proofInvalidTraceV2
    :: UniqueInputs H
    -> NonNegative Int
    -> Property
prop_proofInvalidTraceV2 (UniqueInputs l) (NonNegative i)
    = length l > 1 && i < length l
    ==> runProof (changeProofTraceV2 p) =/= Just (merkleRoot l)
  where
    p = case merkleProof i l of
        Left e -> error (displayException e)
        Right x -> x

prop_proofInvalidStepCountV1
    :: NonEmptyList (MerkleNodeType H)
    -> NonNegative Int
    -> Property
prop_proofInvalidStepCountV1 (NonEmpty l) (NonNegative i)
    = i < length l ==> changeProofStepCountV1 p
  where
    t = V1.merkleTree @H l
    p = case V1.merkleTreeProof (l !! i) i t of
        Left e -> error (displayException e)
        Right x -> x

prop_proofInvalidStepCountV2
    :: NonEmptyList (MerkleNodeType H)
    -> NonNegative Int
    -> Property
prop_proofInvalidStepCountV2 (NonEmpty l) (NonNegative i)
    = i > 0 && i < length l ==> runProof @_ @Maybe p =/=  runProof p'
  where
    p = case merkleProof i l of
        Left e -> error (displayException e)
        Right x -> x
    p' = p { _merkleProofEvidence = unsafeTail (_merkleProofEvidence p) }

    unsafeTail [] = error "tail called on empty list"
    unsafeTail (_:t) = t

prop_proofInvalidObjectHashV1
    :: NonEmptyList (MerkleNodeType H)
    -> NonNegative Int
    -> Property
prop_proofInvalidObjectHashV1 (NonEmpty l) (NonNegative i)
    = 1 < length l && i < length l
    ==> V1.runMerkleProof (changeProofHashV1 p) =/= Just (V1.merkleTreeRoot t)
  where
    t = V1.merkleTree @H l
    p = case V1.merkleTreeProof (l !! i) i t of
        Left e -> error (displayException e)
        Right x -> x

prop_proofInvalidEvidenceHashV2
    :: NonEmptyList (MerkleNodeType H)
    -> NonNegative Int
    -> Property
prop_proofInvalidEvidenceHashV2 (NonEmpty l) (NonNegative i)
    = 1 < length l && i < length l
    ==> runProof (changeProofHashV2 p) =/= Just (merkleRoot l)
  where
    p = case merkleProof i l of
        Left e -> error (displayException e)
        Right x -> x

prop_chainProofV1 :: MerkleTreeChain H -> Property
prop_chainProofV1 (MerkleTreeChain l)
    = V1.runMerkleProof @H p === Just (V1.merkleTreeRoot (snd $ NE.last l))
  where
    p = case V1.merkleTreeProof_ (InputNode "a") l of
        Right x -> x
        Left e -> error $ "test/Main.prop_chainProof: merkleProof failed: " <> show e

prop_chainProofV2 :: TreeV2 H -> Gen Property
prop_chainProofV2 t = do
    pos <- fromIntegral @Int <$> choose (0, fromIntegral (treeV2LeafCount t) - 1)
    let st = NE.reverse (subTree pos t)
    let proofs = (\(x, ls) -> fromJust (merkleProof @H x ls)) <$> st
    return $ t /= TreeEmpty ==> do
        p <- concatProofs @H @Maybe proofs
        r <- runProof @H p
        return $ r === treeV2Root t

prop_encodeProofObjectV1 :: V1.MerkleProof H -> Property
prop_encodeProofObjectV1 p
    = case V1.decodeMerkleProofObject (V1.encodeMerkleProofObject po) of
        Left e -> error (displayException e)
        Right x -> po === x
  where
    po = V1._merkleProofObject p

prop_encodeProofV2 :: MerkleProof H -> Property
prop_encodeProofV2 p
    = case decodeProof @H (encodeProof p) of
        Left e -> error (displayException e)
        Right x -> p === x

prop_encodeProofChainObjectV1 :: MerkleTreeChain H -> Property
prop_encodeProofChainObjectV1 (MerkleTreeChain l)
    = case V1.decodeMerkleProofObject (V1.encodeMerkleProofObject po) of
        Left e -> error (displayException e)
        Right x -> po === x
  where
    p = case V1.merkleTreeProof_ (InputNode "a") l of
        Left e -> error (displayException e)
        Right x -> x
    po = V1._merkleProofObject p

prop_encodeMerkleRoot :: V1.MerkleTree H -> Property
prop_encodeMerkleRoot t
    = case decodeMerkleRoot (encodeMerkleRoot r) of
        Left e -> error (displayException e)
        Right x -> r === x
  where
    r = V1.merkleTreeRoot t

prop_encodeMerkleTreeV1 :: V1.MerkleTree H -> Property
prop_encodeMerkleTreeV1 t
    = case V1.decodeMerkleTree (V1.encodeMerkleTree t) of
        Left e -> error (displayException e)
        Right x -> t === x

-- -------------------------------------------------------------------------- --
-- Misc Specs

proofV2Serialization :: Spec
proofV2Serialization = describe "V2 proof serialization" $ do
    mapM_ (\(n, pos) -> v2SerializationRoundtrip n pos)
        [ (n, pos)
        | n <- [1..32] <> [127, 128, 255, 256, 257, 1024]
        , pos <- [0..n-1]
        ]

v2SerializationRoundtrip :: Natural -> Natural -> Spec
v2SerializationRoundtrip n pos = it msg $ do
    proof <- merkleProof @H (int pos) ls
    shouldReturn (decodeProof @H $ encodeProof proof) proof
  where
    ls = InputNode . B.singleton . int <$> [0 .. n - 1]
    msg = "can serialize proofs of size " <> show n <> " at pos " <> show pos

proofV2Tests :: Spec
proofV2Tests = describe "V2 proof creation and verification" $ do
    mapM_ (\(n, pos) -> v2ProofRoundtrip n pos)
        [ (n, pos)
        | n <- [1..32] <> [127, 128, 255, 256, 257, 1024]
        , pos <- [0..n-1]
        ]

v2ProofRoundtrip :: Natural -> Natural -> Spec
v2ProofRoundtrip n pos = it msg $ do
    proof <- merkleProof @H (int pos) ls
    shouldReturn (runProof @H proof) (merkleRoot ls)
  where
    ls = InputNode . B.singleton . int <$> [0 .. n - 1]
    msg = "can create and verify proof of size " <> show n <> " at pos " <> show pos

