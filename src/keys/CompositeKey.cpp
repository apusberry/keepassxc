/*
*  Copyright (C) 2010 Felix Geyer <debfx@fobos.de>
*  Copyright (C) 2017 KeePassXC Team <team@keepassxc.org>
*
*  This program is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation, either version 2 or (at your option)
*  version 3 of the License.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "CompositeKey.h"
#include <QFile>
#include <QtConcurrent>

#include "core/Global.h"
#include "crypto/CryptoHash.h"

CompositeKey::CompositeKey()
{
}

CompositeKey::CompositeKey(const CompositeKey& key)
{
    *this = key;
}

CompositeKey::~CompositeKey()
{
    clear();
}

void CompositeKey::clear()
{
    qDeleteAll(m_keys);
    m_keys.clear();
    m_challengeResponseKeys.clear();
}

bool CompositeKey::isEmpty() const
{
    return m_keys.isEmpty() && m_challengeResponseKeys.isEmpty();
}

CompositeKey* CompositeKey::clone() const
{
    return new CompositeKey(*this);
}

CompositeKey& CompositeKey::operator=(const CompositeKey& key)
{
    // handle self assignment as that would break when calling clear()
    if (this == &key) {
        return *this;
    }

    clear();

    for (const Key* subKey : asConst(key.m_keys)) {
        addKey(*subKey);
    }
    for (const auto subKey : asConst(key.m_challengeResponseKeys)) {
        addChallengeResponseKey(subKey);
    }

    return *this;
}

/**
 * Get raw key hash as bytes.
 * The key hash does not contain any challenge-response components. To include those,
 * use \link CompositeKey::rawKey() instead.
 *
 * @param masterSeed master seed to challenge or nullptr to exclude challenge-response components
 * @return key hash
 */
QByteArray CompositeKey::rawKey() const
{
    return rawKey(nullptr);
}

/**
 * Get raw key hash as bytes.
 * If <tt>masterSeed</tt> is a nullptr, the returned key hash does not include any
 * challenge-response components.
 *
 * @param masterSeed master seed to challenge or nullptr to exclude challenge-response components
 * @return key hash
 */
QByteArray CompositeKey::rawKey(const QByteArray* masterSeed) const
{
    CryptoHash cryptoHash(CryptoHash::Sha256);

    for (const Key* key : m_keys) {
        cryptoHash.addData(key->rawKey());
    }

    if (masterSeed) {
        QByteArray challengeResult;
        challenge(*masterSeed, challengeResult);
        cryptoHash.addData(challengeResult);
    }

    return cryptoHash.result();
}

/**
 * Transform this composite key.
 * If <tt>masterSeed</tt> is not a nullptr, the transformed key will include all
 * key components, including challenge-response keys.
 *
 * @param kdf key derivation function
 * @param masterSeed master seed to challenge
 * @param result transformed key
 * @return true on success
 */
bool CompositeKey::transform(const Kdf& kdf, QByteArray& result, const QByteArray* masterSeed) const
{
    return kdf.transform(rawKey(masterSeed), result);
}

bool CompositeKey::challenge(const QByteArray& seed, QByteArray& result) const
{
    // if no challenge response was requested, return nothing to
    // maintain backwards compatibility with regular databases.
    if (m_challengeResponseKeys.length() == 0) {
        result.clear();
        return true;
    }

    CryptoHash cryptoHash(CryptoHash::Sha256);

    for (const auto key : m_challengeResponseKeys) {
        // if the device isn't present or fails, return an error
        if (!key->challenge(seed)) {
            qWarning("Failed to issue challenge");
            return false;
        }
        cryptoHash.addData(key->rawKey());
    }

    result = cryptoHash.result();
    return true;
}

void CompositeKey::addKey(const Key& key)
{
    m_keys.append(key.clone());
}

void CompositeKey::addChallengeResponseKey(QSharedPointer<ChallengeResponseKey> key)
{
    m_challengeResponseKeys.append(key);
}
