{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE BangPatterns #-}
{-# LANGUAGE ImportQualifiedPost #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MagicHash #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}

-- |
-- Module: Data.MerkleLog.Utils
-- Copyright: Copyright © 2025 Kadena LLC.
-- License: MIT
-- Maintainer: Lars Kuhtz <lars@kadena.io>
-- Stability: experimental
--
module Data.MerkleLog.Utils
(
-- * Conversion between ByteString and ByteArray
  toByteArray
, fromByteArray

-- * Base64 Encoding
, Base64Encoded(..)
, b64

-- * Byte Swapping
, unI#
, be16
, be32
, be64
, le64

-- * Ints
, int
, natVal_

-- * Misc
, sshow
, tryAllSync
) where

import Control.Exception qualified as E
import Control.Monad.Catch
import Data.Array.Byte
import Data.ByteString qualified as B
import Data.ByteString.Base64.URL qualified as B64
import Data.ByteString.Char8 qualified as B8
import Data.ByteString.Short qualified as BS
import Data.Text qualified as T
import Data.Text.Encoding qualified as T
import GHC.ByteOrder
import GHC.Exts
import GHC.TypeNats
import GHC.Word

-- --------------------------------------------------------------------------
-- Conversion between ByteString and ByteArray

toByteArray :: B.ByteString -> ByteArray
toByteArray = coerce . BS.toShort
{-# INLINE toByteArray #-}

fromByteArray :: ByteArray -> B.ByteString
fromByteArray = BS.fromShort . BS.ShortByteString
{-# INLINE fromByteArray #-}

-- -------------------------------------------------------------------------- --
-- Base64

-- | For use with deriving via
--
newtype Base64Encoded = Base64Encoded ByteArray
    deriving (Eq)

instance Show Base64Encoded where
    show (Base64Encoded b) = B8.unpack
        $ B64.encodeUnpadded
        $ BS.fromShort $ BS.ShortByteString b

b64 :: B.ByteString -> T.Text
b64 = T.decodeUtf8 . B64.encodeUnpadded
{-# INLINE b64 #-}

-- --------------------------------------------------------------------------
-- ByteSwapping

be16 :: Word16 -> Word16
be16
    | targetByteOrder == BigEndian = id
    | otherwise = byteSwap16
{-# INLINE be16 #-}

be32 :: Word32 -> Word32
be32
    | targetByteOrder == BigEndian = id
    | otherwise = byteSwap32
{-# INLINE be32 #-}

be64 :: Word64 -> Word64
be64
    | targetByteOrder == BigEndian = id
    | otherwise = byteSwap64
{-# INLINE be64 #-}

le64 :: Word64 -> Word64
le64
    | targetByteOrder == BigEndian = byteSwap64
    | otherwise = id
{-# INLINE le64 #-}

-- -------------------------------------------------------------------------- --
-- Ints

int :: Integral a => Num b => a -> b
int = fromIntegral
{-# INLINE int #-}

unI# :: Int -> Int#
unI# !(I# i#) = i#
{-# INLINE unI# #-}

natVal_ :: forall n b . KnownNat n => Num b => b
natVal_ = int $ natVal' @n proxy#
{-# INLINE natVal_ #-}

-- -------------------------------------------------------------------------- --
-- Misc

sshow :: Show a => IsString b => a -> b
sshow = fromString . show
{-# INLINE sshow #-}

tryAllSync :: IO a -> IO (Either E.SomeException a)
tryAllSync act = E.try act >>= \case
    Left e -> case fromException (toException e) of
        Just (E.SomeAsyncException _) -> E.throw e
        Nothing -> return $ Left e
    Right r -> return $ Right r
{-# INLINE tryAllSync #-}

