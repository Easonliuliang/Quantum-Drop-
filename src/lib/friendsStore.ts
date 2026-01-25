// Friends storage using localStorage

export interface Friend {
  code: string;
  addedAt: number;
  nickname?: string;
}

const FRIENDS_STORAGE_KEY = 'quantum_drop_friends';

export function loadFriends(): Friend[] {
  try {
    const stored = localStorage.getItem(FRIENDS_STORAGE_KEY);
    if (!stored) return [];
    return JSON.parse(stored) as Friend[];
  } catch {
    return [];
  }
}

export function saveFriends(friends: Friend[]): void {
  try {
    localStorage.setItem(FRIENDS_STORAGE_KEY, JSON.stringify(friends));
  } catch {
    // Storage full or unavailable
  }
}

export function addFriend(code: string, nickname?: string): Friend | null {
  const friends = loadFriends();
  // Check for duplicate
  if (friends.some(f => f.code === code)) {
    return null;
  }
  const newFriend: Friend = {
    code,
    addedAt: Date.now(),
    nickname,
  };
  friends.push(newFriend);
  saveFriends(friends);
  return newFriend;
}

export function removeFriend(code: string): boolean {
  const friends = loadFriends();
  const index = friends.findIndex(f => f.code === code);
  if (index === -1) return false;
  friends.splice(index, 1);
  saveFriends(friends);
  return true;
}

export function updateFriendNickname(code: string, nickname: string): boolean {
  const friends = loadFriends();
  const friend = friends.find(f => f.code === code);
  if (!friend) return false;
  friend.nickname = nickname;
  saveFriends(friends);
  return true;
}
