/*
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

#include "Kdbx4XmlReader.h"

#include <QBuffer>
#include <QFile>

#include "core/Endian.h"
#include "core/DatabaseIcons.h"
#include "core/Metadata.h"
#include "core/Tools.h"
#include "format/KeePass2RandomStream.h"
#include "streams/QtIOCompressor"

typedef QPair<QString, QString> StringPair;

Kdbx4XmlReader::Kdbx4XmlReader()
    : m_randomStream(nullptr)
    , m_db(nullptr)
    , m_meta(nullptr)
    , m_tmpParent(nullptr)
    , m_error(false)
    , m_strictMode(false)
{
}

Kdbx4XmlReader::Kdbx4XmlReader(QHash<QString, QByteArray>& binaryPool)
    : Kdbx4XmlReader()
{
    m_binaryPool = binaryPool;
}

void Kdbx4XmlReader::setStrictMode(bool strictMode)
{
    m_strictMode = strictMode;
}

void Kdbx4XmlReader::readDatabase(QIODevice* device, Database* db, KeePass2RandomStream* randomStream)
{
    m_error = false;
    m_errorStr.clear();

    m_xml.clear();
    m_xml.setDevice(device);

    m_db = db;
    m_meta = m_db->metadata();
    m_meta->setUpdateDatetime(false);

    m_randomStream = randomStream;
    m_headerHash.clear();

    m_tmpParent.reset(new Group());

    bool rootGroupParsed = false;

    if (m_xml.hasError()) {
        raiseError(QString("XML parsing failure: %1").arg(m_xml.error()));
        return;
    }

    if (m_xml.readNextStartElement() && m_xml.name() == "KeePassFile") {
        rootGroupParsed = parseKeePassFile();
    }

    if (!rootGroupParsed) {
        raiseError("No root group");
        return;
    }

    if (!m_tmpParent->children().isEmpty()) {
        qWarning("Kdbx4XmlReader::readDatabase: found %d invalid group reference(s)",
                 m_tmpParent->children().size());
    }

    if (!m_tmpParent->entries().isEmpty()) {
        qWarning("Kdbx4XmlReader::readDatabase: found %d invalid entry reference(s)",
                 m_tmpParent->children().size());
    }

    const QSet<QString> poolKeys = m_binaryPool.keys().toSet();
    const QSet<QString> entryKeys = m_binaryMap.keys().toSet();
    const QSet<QString> unmappedKeys = entryKeys - poolKeys;
    const QSet<QString> unusedKeys = poolKeys - entryKeys;

    if (!unmappedKeys.isEmpty()) {
        qWarning("Unmapped keys left.");
    }

    for (const QString& key : unusedKeys) {
        qWarning("Kdbx4XmlReader::readDatabase: found unused key \"%s\"", qPrintable(key));
    }

    QHash<QString, QPair<Entry*, QString> >::const_iterator i;
    for (i = m_binaryMap.constBegin(); i != m_binaryMap.constEnd(); ++i) {
        const QPair<Entry*, QString>& target = i.value();
        target.first->attachments()->set(target.second, m_binaryPool[i.key()]);
    }

    m_meta->setUpdateDatetime(true);

    QHash<Uuid, Group*>::const_iterator iGroup;
    for (iGroup = m_groups.constBegin(); iGroup != m_groups.constEnd(); ++iGroup) {
        iGroup.value()->setUpdateTimeinfo(true);
    }

    QHash<Uuid, Entry*>::const_iterator iEntry;
    for (iEntry = m_entries.constBegin(); iEntry != m_entries.constEnd(); ++iEntry) {
        iEntry.value()->setUpdateTimeinfo(true);

        const QList<Entry*> historyItems = iEntry.value()->historyItems();
        for (Entry* histEntry : historyItems) {
            histEntry->setUpdateTimeinfo(true);
        }
    }
}

Database* Kdbx4XmlReader::readDatabase(QIODevice* device)
{
    auto db = new Database();
    readDatabase(device, db);
    return db;
}

Database* Kdbx4XmlReader::readDatabase(const QString& filename)
{
    QFile file(filename);
    file.open(QIODevice::ReadOnly);
    return readDatabase(&file);
}

bool Kdbx4XmlReader::hasError()
{
    return m_error || m_xml.hasError();
}

QString Kdbx4XmlReader::errorString()
{
    if (m_error) {
        return m_errorStr;
    }

    if (m_xml.hasError()) {
        return QString("XML error:\n%1\nLine %2, column %3")
                .arg(m_xml.errorString())
                .arg(m_xml.lineNumber())
                .arg(m_xml.columnNumber());
    }

    return QString();
}

void Kdbx4XmlReader::raiseError(const QString& errorMessage)
{
    m_error = true;
    m_errorStr = errorMessage;
}

QByteArray Kdbx4XmlReader::headerHash()
{
    return m_headerHash;
}

bool Kdbx4XmlReader::parseKeePassFile()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "KeePassFile");

    bool rootElementFound = false;
    bool rootParsedSuccessfully = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Meta") {
            parseMeta();
            continue;
        }

        if (m_xml.name() == "Root") {
            if (rootElementFound) {
                rootParsedSuccessfully = false;
                qWarning("Multiple root elements");
            } else {
                rootParsedSuccessfully = parseRoot();
                rootElementFound = true;
            }
            continue;
        }

        skipCurrentElement();
    }

    return rootParsedSuccessfully;
}

void Kdbx4XmlReader::parseMeta()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Meta");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Generator") {
            m_meta->setGenerator(readString());
        } else if (m_xml.name() == "HeaderHash") {
            m_headerHash = readBinary();
        } else if (m_xml.name() == "DatabaseName") {
            m_meta->setName(readString());
        } else if (m_xml.name() == "DatabaseNameChanged") {
            m_meta->setNameChanged(readDateTime());
        } else if (m_xml.name() == "DatabaseDescription") {
            m_meta->setDescription(readString());
        } else if (m_xml.name() == "DatabaseDescriptionChanged") {
            m_meta->setDescriptionChanged(readDateTime());
        } else if (m_xml.name() == "DefaultUserName") {
            m_meta->setDefaultUserName(readString());
        } else if (m_xml.name() == "DefaultUserNameChanged") {
            m_meta->setDefaultUserNameChanged(readDateTime());
        } else if (m_xml.name() == "MaintenanceHistoryDays") {
            m_meta->setMaintenanceHistoryDays(readNumber());
        } else if (m_xml.name() == "Color") {
            m_meta->setColor(readColor());
        } else if (m_xml.name() == "MasterKeyChanged") {
            m_meta->setMasterKeyChanged(readDateTime());
        } else if (m_xml.name() == "MasterKeyChangeRec") {
            m_meta->setMasterKeyChangeRec(readNumber());
        } else if (m_xml.name() == "MasterKeyChangeForce") {
            m_meta->setMasterKeyChangeForce(readNumber());
        } else if (m_xml.name() == "MemoryProtection") {
            parseMemoryProtection();
        } else if (m_xml.name() == "CustomIcons") {
            parseCustomIcons();
        } else if (m_xml.name() == "RecycleBinEnabled") {
            m_meta->setRecycleBinEnabled(readBool());
        } else if (m_xml.name() == "RecycleBinUUID") {
            m_meta->setRecycleBin(getGroup(readUuid()));
        } else if (m_xml.name() == "RecycleBinChanged") {
            m_meta->setRecycleBinChanged(readDateTime());
        } else if (m_xml.name() == "EntryTemplatesGroup") {
            m_meta->setEntryTemplatesGroup(getGroup(readUuid()));
        } else if (m_xml.name() == "EntryTemplatesGroupChanged") {
            m_meta->setEntryTemplatesGroupChanged(readDateTime());
        } else if (m_xml.name() == "LastSelectedGroup") {
            m_meta->setLastSelectedGroup(getGroup(readUuid()));
        } else if (m_xml.name() == "LastTopVisibleGroup") {
            m_meta->setLastTopVisibleGroup(getGroup(readUuid()));
        } else if (m_xml.name() == "HistoryMaxItems") {
            int value = readNumber();
            if (value >= -1) {
                m_meta->setHistoryMaxItems(value);
            } else {
                qWarning("HistoryMaxItems invalid number");
            }
        } else if (m_xml.name() == "HistoryMaxSize") {
            int value = readNumber();
            if (value >= -1) {
                m_meta->setHistoryMaxSize(value);
            } else {
                qWarning("HistoryMaxSize invalid number");
            }
        } else if (m_xml.name() == "Binaries") {
            parseBinaries();
        } else if (m_xml.name() == "CustomData") {
            parseCustomData();
        } else if (m_xml.name() == "SettingsChanged") {
            m_meta->setSettingsChanged(readDateTime());
        } else {
            skipCurrentElement();
        }
    }
}

void Kdbx4XmlReader::parseMemoryProtection()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "MemoryProtection");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "ProtectTitle") {
            m_meta->setProtectTitle(readBool());
        } else if (m_xml.name() == "ProtectUserName") {
            m_meta->setProtectUsername(readBool());
        } else if (m_xml.name() == "ProtectPassword") {
            m_meta->setProtectPassword(readBool());
        } else if (m_xml.name() == "ProtectURL") {
            m_meta->setProtectUrl(readBool());
        } else if (m_xml.name() == "ProtectNotes") {
            m_meta->setProtectNotes(readBool());
        } else {
            skipCurrentElement();
        }
    }
}

void Kdbx4XmlReader::parseCustomIcons()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "CustomIcons");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Icon") {
            parseIcon();
        } else {
            skipCurrentElement();
        }
    }
}

void Kdbx4XmlReader::parseIcon()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Icon");

    Uuid uuid;
    QImage icon;
    bool uuidSet = false;
    bool iconSet = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "UUID") {
            uuid = readUuid();
            uuidSet = !uuid.isNull();
        } else if (m_xml.name() == "Data") {
            icon.loadFromData(readBinary());
            iconSet = true;
        } else {
            skipCurrentElement();
        }
    }

    if (uuidSet && iconSet) {
        m_meta->addCustomIcon(uuid, icon);
        return;
    }

    raiseError("Missing icon uuid or data");
}

void Kdbx4XmlReader::parseBinaries()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Binaries");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() != "Binary") {
            skipCurrentElement();
            continue;
        }

        QXmlStreamAttributes attr = m_xml.attributes();

        QString id = attr.value("ID").toString();

        QByteArray data;
        if (attr.value("Compressed").compare(QLatin1String("True"), Qt::CaseInsensitive) == 0) {
            data = readCompressedBinary();
        } else {
            data = readBinary();
        }

        if (m_binaryPool.contains(id)) {
            qWarning("Kdbx4XmlReader::parseBinaries: overwriting binary item \"%s\"",
                     qPrintable(id));
        }

        m_binaryPool.insert(id, data);
    }
}

void Kdbx4XmlReader::parseCustomData()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "CustomData");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Item") {
            parseCustomDataItem();
            continue;
        }
        skipCurrentElement();
    }
}

void Kdbx4XmlReader::parseCustomDataItem()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Item");

    QString key;
    QString value;
    bool keySet = false;
    bool valueSet = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Key") {
            key = readString();
            keySet = true;
        } else if (m_xml.name() == "Value") {
            value = readString();
            valueSet = true;
        } else {
            skipCurrentElement();
        }
    }

    if (keySet && valueSet) {
        m_meta->addCustomField(key, value);
        return;
    }

    raiseError("Missing custom data key or value");
}

bool Kdbx4XmlReader::parseRoot()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Root");

    bool groupElementFound = false;
    bool groupParsedSuccessfully = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Group") {
            if (groupElementFound) {
                groupParsedSuccessfully = false;
                raiseError("Multiple group elements");
                continue;
            }

            Group* rootGroup = parseGroup();
            if (rootGroup) {
                Group* oldRoot = m_db->rootGroup();
                m_db->setRootGroup(rootGroup);
                delete oldRoot;
                groupParsedSuccessfully = true;
            }

            groupElementFound = true;
        } else if (m_xml.name() == "DeletedObjects") {
            parseDeletedObjects();
        } else {
            skipCurrentElement();
        }
    }

    return groupParsedSuccessfully;
}

Group* Kdbx4XmlReader::parseGroup()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Group");

    auto group = new Group();
    group->setUpdateTimeinfo(false);
    QList<Group*> children;
    QList<Entry*> entries;
    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "UUID") {
            Uuid uuid = readUuid();
            if (uuid.isNull()) {
                if (m_strictMode) {
                    raiseError("Null group uuid");
                } else {
                    group->setUuid(Uuid::random());
                }
            } else {
                group->setUuid(uuid);
            }
            continue;
        }
        if (m_xml.name() == "Name") {
            group->setName(readString());
            continue;
        }
        if (m_xml.name() == "Notes") {
            group->setNotes(readString());
            continue;
        }
        if (m_xml.name() == "IconID") {
            int iconId = readNumber();
            if (iconId < 0) {
                if (m_strictMode) {
                    raiseError("Invalid group icon number");
                }
                iconId = 0;
            } else if (iconId >= DatabaseIcons::IconCount) {
                qWarning("Kdbx4XmlReader::parseGroup: icon id \"%d\" not supported", iconId);
                iconId = DatabaseIcons::IconCount - 1;
            }

            group->setIcon(iconId);
            continue;
        }
        if (m_xml.name() == "CustomIconUUID") {
            Uuid uuid = readUuid();
            if (!uuid.isNull()) {
                group->setIcon(uuid);
            }
            continue;
        }
        if (m_xml.name() == "Times") {
            group->setTimeInfo(parseTimes());
            continue;
        }
        if (m_xml.name() == "IsExpanded") {
            group->setExpanded(readBool());
            continue;
        }
        if (m_xml.name() == "DefaultAutoTypeSequence") {
            group->setDefaultAutoTypeSequence(readString());
            continue;
        }
        if (m_xml.name() == "EnableAutoType") {
            QString str = readString();

            if (str.compare("null", Qt::CaseInsensitive) == 0) {
                group->setAutoTypeEnabled(Group::Inherit);
            } else if (str.compare("true", Qt::CaseInsensitive) == 0) {
                group->setAutoTypeEnabled(Group::Enable);
            } else if (str.compare("false", Qt::CaseInsensitive) == 0) {
                group->setAutoTypeEnabled(Group::Disable);
            } else {
                raiseError("Invalid EnableAutoType value");
            }
            continue;
        }
        if (m_xml.name() == "EnableSearching") {
            QString str = readString();

            if (str.compare("null", Qt::CaseInsensitive) == 0) {
                group->setSearchingEnabled(Group::Inherit);
            } else if (str.compare("true", Qt::CaseInsensitive) == 0) {
                group->setSearchingEnabled(Group::Enable);
            } else if (str.compare("false", Qt::CaseInsensitive) == 0) {
                group->setSearchingEnabled(Group::Disable);
            } else {
                raiseError("Invalid EnableSearching value");
            }
            continue;
        }
        if (m_xml.name() == "LastTopVisibleEntry") {
            group->setLastTopVisibleEntry(getEntry(readUuid()));
            continue;
        }
        if (m_xml.name() == "Group") {
            Group* newGroup = parseGroup();
            if (newGroup) {
                children.append(newGroup);
            }
            continue;
        }
        if (m_xml.name() == "Entry") {
            Entry* newEntry = parseEntry(false);
            if (newEntry) {
                entries.append(newEntry);
            }
            continue;
        }

        skipCurrentElement();
    }

    if (group->uuid().isNull() && !m_strictMode) {
        group->setUuid(Uuid::random());
    }

    if (!group->uuid().isNull()) {
        Group* tmpGroup = group;
        group = getGroup(tmpGroup->uuid());
        group->copyDataFrom(tmpGroup);
        group->setUpdateTimeinfo(false);
        delete tmpGroup;
    } else if (!hasError()) {
        raiseError("No group uuid found");
    }

    for (Group* child : asConst(children)) {
        child->setParent(group);
    }

    for (Entry* entry : asConst(entries)) {
        entry->setGroup(group);
    }

    return group;
}

void Kdbx4XmlReader::parseDeletedObjects()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "DeletedObjects");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "DeletedObject") {
            parseDeletedObject();
        } else {
            skipCurrentElement();
        }
    }
}

void Kdbx4XmlReader::parseDeletedObject()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "DeletedObject");

    DeletedObject delObj{};

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "UUID") {
            Uuid uuid = readUuid();
            if (uuid.isNull()) {
                if (m_strictMode) {
                    raiseError("Null DeleteObject uuid");
                }
                continue;
            }
            delObj.uuid = uuid;
            continue;
        }
        if (m_xml.name() == "DeletionTime") {
            delObj.deletionTime = readDateTime();
            continue;
        }
        skipCurrentElement();
    }

    if (!delObj.uuid.isNull() && !delObj.deletionTime.isNull()) {
        m_db->addDeletedObject(delObj);
        return;
    }

    if (m_strictMode) {
        raiseError("Missing DeletedObject uuid or time");
    }
}

Entry* Kdbx4XmlReader::parseEntry(bool history)
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Entry");

    auto entry = new Entry();
    entry->setUpdateTimeinfo(false);
    QList<Entry*> historyItems;
    QList<StringPair> binaryRefs;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "UUID") {
            Uuid uuid = readUuid();
            if (uuid.isNull()) {
                if (m_strictMode) {
                    raiseError("Null entry uuid");
                } else {
                    entry->setUuid(Uuid::random());
                }
            } else {
                entry->setUuid(uuid);
            }
            continue;
        }
        if (m_xml.name() == "IconID") {
            int iconId = readNumber();
            if (iconId < 0) {
                if (m_strictMode) {
                    raiseError("Invalid entry icon number");
                }
                iconId = 0;
            }
            entry->setIcon(iconId);
            continue;
        }
        if (m_xml.name() == "CustomIconUUID") {
            Uuid uuid = readUuid();
            if (!uuid.isNull()) {
                entry->setIcon(uuid);
            }
            continue;
        }if (m_xml.name() == "ForegroundColor") {
            entry->setForegroundColor(readColor());
            continue;
        }
        if (m_xml.name() == "BackgroundColor") {
            entry->setBackgroundColor(readColor());
            continue;
        }
        if (m_xml.name() == "OverrideURL") {
            entry->setOverrideUrl(readString());
            continue;
        }
        if (m_xml.name() == "Tags") {
            entry->setTags(readString());
            continue;
        }
        if (m_xml.name() == "Times") {
            entry->setTimeInfo(parseTimes());
            continue;
        }
        if (m_xml.name() == "String") {
            parseEntryString(entry);
            continue;
        }
        if (m_xml.name() == "Binary") {
            QPair<QString, QString> ref = parseEntryBinary(entry);
            if (!ref.first.isNull() && !ref.second.isNull()) {
                binaryRefs.append(ref);
            }
            continue;
        }
        if (m_xml.name() == "AutoType") {
            parseAutoType(entry);
            continue;
        }
        if (m_xml.name() == "History") {
            if (history) {
                raiseError("History element in history entry");
            } else {
                historyItems = parseEntryHistory();
            }
            continue;
        }

        skipCurrentElement();
    }

    if (entry->uuid().isNull() && !m_strictMode) {
        entry->setUuid(Uuid::random());
    }

    if (!entry->uuid().isNull()) {
        if (history) {
            entry->setUpdateTimeinfo(false);
        } else {
            Entry* tmpEntry = entry;

            entry = getEntry(tmpEntry->uuid());
            entry->copyDataFrom(tmpEntry);
            entry->setUpdateTimeinfo(false);

            delete tmpEntry;
        }
    } else if (!hasError()) {
        raiseError("No entry uuid found");
    }

    for (Entry* historyItem : asConst(historyItems)) {
        if (historyItem->uuid() != entry->uuid()) {
            if (m_strictMode) {
                raiseError("History element with different uuid");
            } else {
                historyItem->setUuid(entry->uuid());
            }
        }
        entry->addHistoryItem(historyItem);
    }

    for (const StringPair& ref : asConst(binaryRefs)) {
        m_binaryMap.insertMulti(ref.first, qMakePair(entry, ref.second));
    }

    return entry;
}

void Kdbx4XmlReader::parseEntryString(Entry* entry)
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "String");

    QString key;
    QString value;
    bool protect = false;
    bool keySet = false;
    bool valueSet = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Key") {
            key = readString();
            keySet = true;
            continue;
        }

        if (m_xml.name() == "Value") {
            QXmlStreamAttributes attr = m_xml.attributes();
            value = readString();

            bool isProtected = attr.value("Protected") == "True";
            bool protectInMemory = attr.value("ProtectInMemory") == "True";

            if (isProtected && !value.isEmpty()) {
                if (m_randomStream) {
                    QByteArray ciphertext = QByteArray::fromBase64(value.toLatin1());
                    bool ok;
                    QByteArray plaintext = m_randomStream->process(ciphertext, &ok);
                    if (!ok) {
                        value.clear();
                        raiseError(m_randomStream->errorString());
                    } else {
                        value = QString::fromUtf8(plaintext);
                    }
                } else {
                    raiseError("Unable to decrypt entry string");
                    continue;
                }
            }

            protect = isProtected || protectInMemory;
            valueSet = true;
            continue;
        }

        skipCurrentElement();
    }

    if (keySet && valueSet) {
        // the default attributes are always there so additionally check if it's empty
        if (entry->attributes()->hasKey(key) && !entry->attributes()->value(key).isEmpty()) {
            raiseError("Duplicate custom attribute found");
            return;
        }
        entry->attributes()->set(key, value, protect);
        return;
    }

    raiseError("Entry string key or value missing");
}

QPair<QString, QString> Kdbx4XmlReader::parseEntryBinary(Entry* entry)
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Binary");

    QPair<QString, QString> poolRef;

    QString key;
    QByteArray value;
    bool keySet = false;
    bool valueSet = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Key") {
            key = readString();
            keySet = true;
            continue;
        }
        if (m_xml.name() == "Value") {
            QXmlStreamAttributes attr = m_xml.attributes();

            if (attr.hasAttribute("Ref")) {
                poolRef = qMakePair(attr.value("Ref").toString(), key);
                m_xml.skipCurrentElement();
            } else {
                // format compatibility
                value = readBinary();
                bool isProtected = attr.hasAttribute("Protected")
                        && (attr.value("Protected") == "True");

                if (isProtected && !value.isEmpty()) {
                    if (!m_randomStream->processInPlace(value)) {
                        raiseError(m_randomStream->errorString());
                    }
                }
            }

            valueSet = true;
            continue;
        }
        skipCurrentElement();
    }

    if (keySet && valueSet) {
        if (entry->attachments()->hasKey(key)) {
            raiseError("Duplicate attachment found");
        } else {
            entry->attachments()->set(key, value);
        }
    } else {
        raiseError("Entry binary key or value missing");
    }

    return poolRef;
}

void Kdbx4XmlReader::parseAutoType(Entry* entry)
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "AutoType");

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Enabled") {
            entry->setAutoTypeEnabled(readBool());
        } else if (m_xml.name() == "DataTransferObfuscation") {
            entry->setAutoTypeObfuscation(readNumber());
        } else if (m_xml.name() == "DefaultSequence") {
            entry->setDefaultAutoTypeSequence(readString());
        } else if (m_xml.name() == "Association") {
            parseAutoTypeAssoc(entry);
        } else {
            skipCurrentElement();
        }
    }
}

void Kdbx4XmlReader::parseAutoTypeAssoc(Entry* entry)
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Association");

    AutoTypeAssociations::Association assoc;
    bool windowSet = false;
    bool sequenceSet = false;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Window") {
            assoc.window = readString();
            windowSet = true;
        } else if (m_xml.name() == "KeystrokeSequence") {
            assoc.sequence = readString();
            sequenceSet = true;
        } else {
            skipCurrentElement();
        }
    }

    if (windowSet && sequenceSet) {
        entry->autoTypeAssociations()->add(assoc);
        return;
    }
    raiseError("Auto-type association window or sequence missing");
}

QList<Entry*> Kdbx4XmlReader::parseEntryHistory()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "History");

    QList<Entry*> historyItems;

    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "Entry") {
            historyItems.append(parseEntry(true));
        } else {
            skipCurrentElement();
        }
    }

    return historyItems;
}

TimeInfo Kdbx4XmlReader::parseTimes()
{
    Q_ASSERT(m_xml.isStartElement() && m_xml.name() == "Times");

    TimeInfo timeInfo;
    while (!m_xml.hasError() && m_xml.readNextStartElement()) {
        if (m_xml.name() == "LastModificationTime") {
            timeInfo.setLastModificationTime(readDateTime());
        } else if (m_xml.name() == "CreationTime") {
            timeInfo.setCreationTime(readDateTime());
        } else if (m_xml.name() == "LastAccessTime") {
            timeInfo.setLastAccessTime(readDateTime());
        } else if (m_xml.name() == "ExpiryTime") {
            timeInfo.setExpiryTime(readDateTime());
        } else if (m_xml.name() == "Expires") {
            timeInfo.setExpires(readBool());
        } else if (m_xml.name() == "UsageCount") {
            timeInfo.setUsageCount(readNumber());
        } else if (m_xml.name() == "LocationChanged") {
            timeInfo.setLocationChanged(readDateTime());
        } else {
            skipCurrentElement();
        }
    }

    return timeInfo;
}

QString Kdbx4XmlReader::readString()
{
    return m_xml.readElementText();
}

bool Kdbx4XmlReader::readBool()
{
    QString str = readString();

    if (str.compare("True", Qt::CaseInsensitive) == 0) {
        return true;
    }
    if (str.compare("False", Qt::CaseInsensitive) == 0) {
        return false;
    }
    if (str.length() == 0) {
        return false;
    }
    raiseError("Invalid bool value");
    return false;
}

QDateTime Kdbx4XmlReader::readDateTime()
{
    static QRegularExpression b64regex("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$");
    QString str = readString();

    if (b64regex.match(str).hasMatch()) {
        QByteArray secsBytes = QByteArray::fromBase64(str.toUtf8()).leftJustified(8, '\0', true).left(8);
        qint64 secs = Endian::bytesToSizedInt<quint64>(secsBytes, KeePass2::BYTEORDER);
        return QDateTime(QDate(1, 1, 1), QTime(0, 0, 0, 0), Qt::UTC).addSecs(secs);
    }

    QDateTime dt = QDateTime::fromString(str, Qt::ISODate);
    if (dt.isValid()) {
        return dt;
    }

    if (m_strictMode) {
        raiseError("Invalid date time value");
    }

    return QDateTime::currentDateTimeUtc();
}

QColor Kdbx4XmlReader::readColor()
{
    QString colorStr = readString();

    if (colorStr.isEmpty()) {
        return {};
    }

    if (colorStr.length() != 7 || colorStr[0] != '#') {
        if (m_strictMode) {
            raiseError("Invalid color value");
        }
        return {};
    }

    QColor color;
    for (int i = 0; i <= 2; ++i) {
        QString rgbPartStr = colorStr.mid(1 + 2 * i, 2);
        bool ok;
        int rgbPart = rgbPartStr.toInt(&ok, 16);
        if (!ok || rgbPart > 255) {
            if (m_strictMode) {
                raiseError("Invalid color rgb part");
            }
            return {};
        }

        if (i == 0) {
            color.setRed(rgbPart);
        } else if (i == 1) {
            color.setGreen(rgbPart);
        } else {
            color.setBlue(rgbPart);
        }
    }

    return color;
}

int Kdbx4XmlReader::readNumber()
{
    bool ok;
    int result = readString().toInt(&ok);
    if (!ok) {
        raiseError("Invalid number value");
    }
    return result;
}

Uuid Kdbx4XmlReader::readUuid()
{
    QByteArray uuidBin = readBinary();
    if (uuidBin.isEmpty()) {
        return {};
    }
    if (uuidBin.length() != Uuid::Length) {
        if (m_strictMode) {
            raiseError("Invalid uuid value");
        }
        return {};
    }
    return Uuid(uuidBin);
}

QByteArray Kdbx4XmlReader::readBinary()
{
    return QByteArray::fromBase64(readString().toLatin1());
}

QByteArray Kdbx4XmlReader::readCompressedBinary()
{
    QByteArray rawData = readBinary();

    QBuffer buffer(&rawData);
    buffer.open(QIODevice::ReadOnly);

    QtIOCompressor compressor(&buffer);
    compressor.setStreamFormat(QtIOCompressor::GzipFormat);
    compressor.open(QIODevice::ReadOnly);

    QByteArray result;
    if (!Tools::readAllFromDevice(&compressor, result)) {
        raiseError("Unable to decompress binary");
    }
    return result;
}

Group* Kdbx4XmlReader::getGroup(const Uuid& uuid)
{
    if (uuid.isNull()) {
        return nullptr;
    }

    if (m_groups.contains(uuid)) {
        return m_groups.value(uuid);
    }

    auto group = new Group();
    group->setUpdateTimeinfo(false);
    group->setUuid(uuid);
    group->setParent(m_tmpParent.data());
    m_groups.insert(uuid, group);
    return group;
}

Entry* Kdbx4XmlReader::getEntry(const Uuid& uuid)
{
    if (uuid.isNull()) {
        return nullptr;
    }

    if (m_entries.contains(uuid)) {
        return m_entries.value(uuid);
    }

    auto entry = new Entry();
    entry->setUpdateTimeinfo(false);
    entry->setUuid(uuid);
    entry->setGroup(m_tmpParent.data());
    m_entries.insert(uuid, entry);
    return entry;
}

void Kdbx4XmlReader::skipCurrentElement()
{
    qWarning("Kdbx4XmlReader::skipCurrentElement: skip element \"%s\"", qPrintable(m_xml.name().toString()));
    m_xml.skipCurrentElement();
}
