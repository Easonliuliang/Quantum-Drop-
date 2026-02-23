// Friends storage using Tauri fs for persistence

import { BaseDirectory, readTextFile, writeTextFile } from "@tauri-apps/plugin-fs";

export interface Friend {
  id: string;           // 唯一标识（公钥哈希）
  publicKey: string;    // 对方公钥
  deviceName: string;   // 设备名称
  nickname?: string;    // 用户设置的昵称
  addedAt: number;      // 添加时间
  lastSeen?: number;    // 最后在线时间
}

const FRIENDS_FILE = "friends.json";

let friendsCache: Friend[] | null = null;

export async function loadFriends(): Promise<Friend[]> {
  if (friendsCache !== null) return friendsCache;

  try {
    const content = await readTextFile(FRIENDS_FILE, { baseDir: BaseDirectory.AppData });
    friendsCache = JSON.parse(content) as Friend[];
    return friendsCache;
  } catch {
    friendsCache = [];
    return [];
  }
}

export async function saveFriends(friends: Friend[]): Promise<void> {
  friendsCache = friends;
  try {
    await writeTextFile(FRIENDS_FILE, JSON.stringify(friends, null, 2), { baseDir: BaseDirectory.AppData });
  } catch (err) {
    console.error("保存好友列表失败:", err);
  }
}

export async function addFriend(friend: Omit<Friend, "addedAt">): Promise<Friend | null> {
  const friends = await loadFriends();
  // 检查重复（通过公钥）
  if (friends.some(f => f.publicKey === friend.publicKey)) {
    return null;
  }
  const newFriend: Friend = {
    ...friend,
    addedAt: Date.now(),
  };
  friends.push(newFriend);
  await saveFriends(friends);
  return newFriend;
}

export async function removeFriend(id: string): Promise<boolean> {
  const friends = await loadFriends();
  const index = friends.findIndex(f => f.id === id);
  if (index === -1) return false;
  friends.splice(index, 1);
  await saveFriends(friends);
  return true;
}

export async function updateFriend(id: string, updates: Partial<Friend>): Promise<boolean> {
  const friends = await loadFriends();
  const friend = friends.find(f => f.id === id);
  if (!friend) return false;
  Object.assign(friend, updates);
  await saveFriends(friends);
  return true;
}

export async function isFriend(publicKey: string): Promise<boolean> {
  const friends = await loadFriends();
  return friends.some(f => f.publicKey === publicKey);
}
