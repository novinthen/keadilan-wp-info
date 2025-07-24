import React, { useState, useEffect, useRef } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut, signInAnonymously, signInWithCustomToken, sendPasswordResetEmail } from 'firebase/auth';
import { getFirestore, doc, getDoc, setDoc, addDoc, collection, onSnapshot, query, where, getDocs, updateDoc, serverTimestamp } from 'firebase/firestore';
import { setLogLevel } from 'firebase/firestore';

// --- Helper Functions & Initial Config ---

// This new block correctly handles configuration for both Vercel and local development.
let firebaseConfig;

if (process.env.REACT_APP_FIREBASE_CONFIG) {
  // Use the environment variable on Vercel
  firebaseConfig = JSON.parse(process.env.REACT_APP_FIREBASE_CONFIG);
} else if (typeof __firebase_config !== 'undefined') {
  // Use the config from the immersive environment
  firebaseConfig = JSON.parse(__firebase_config);
} else {
  // Fallback for local development if no environment variable is set
  // IMPORTANT: Do not commit real keys to GitHub. This is a placeholder.
  console.warn("Firebase config not found in environment variables. Using placeholder.");
  firebaseConfig = {
    apiKey: "YOUR_API_KEY",
    authDomain: "YOUR_AUTH_DOMAIN",
    projectId: "YOUR_PROJECT_ID",
    storageBucket: "YOUR_STORAGE_BUCKET",
    messagingSenderId: "YOUR_MESSAGING_SENDER_ID",
    appId: "YOUR_APP_ID"
  };
}


// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
setLogLevel('debug'); // For detailed console logs

// App ID - crucial for Firestore paths
const appId = typeof __app_id !== 'undefined' ? __app_id : 'keadilan-wp-info';

// Predefined user roles and cabangs
const CABANGS = ["KEPONG", "BATU", "WANGSA MAJU", "SEGAMBUT", "SETIAWANGSA", "TITIWANGSA", "BUKIT BINTANG", "LEMBAH PANTAI", "SEPUTEH", "CHERAS", "BANDAR TUN RAZAK", "PUTRAJAYA"];
const ROLES = ["KC", "TKC", "NKC1", "NKC2", "NKC3", "SUC", "KPC"];

// --- Helper to log activity ---
const logUserActivity = async (userId, type, details = {}) => {
    if (!userId) return;
    try {
        const logCollectionRef = collection(db, `artifacts/${appId}/users/${userId}/activityLog`);
        await addDoc(logCollectionRef, {
            type,
            timestamp: serverTimestamp(),
            ipAddress: '127.0.0.1 (demo)', // Placeholder IP
            ...details,
        });
    } catch (error) {
        console.error("Error logging activity:", error);
    }
};


// --- Main App Component ---

export default function App() {
    const [user, setUser] = useState(null);
    const [authReady, setAuthReady] = useState(false);
    const [userData, setUserData] = useState(null);
    const [view, setView] = useState('login'); // 'login', 'dashboard', 'admin'
    const [error, setError] = useState('');

    // --- Authentication Management ---
    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
            if (firebaseUser && !firebaseUser.isAnonymous) {
                const userDocRef = doc(db, `artifacts/${appId}/users`, firebaseUser.uid);
                const userDocSnap = await getDoc(userDocRef);

                if (userDocSnap.exists()) {
                    const data = userDocSnap.data();
                    setUser(firebaseUser);
                    setUserData(data);
                    setView(data.isAdmin ? 'admin' : 'dashboard');
                     if (data.lastLogin === null || (serverTimestamp.now().seconds - data.lastLogin?.seconds > 60)) {
                        await updateDoc(userDocRef, { lastLogin: serverTimestamp() });
                        logUserActivity(firebaseUser.uid, 'LOGIN_SUCCESS');
                    }
                } else {
                    console.error("User document not found for UID:", firebaseUser.uid);
                    setError("Your user profile could not be found. Please contact an admin.");
                    await signOut(auth);
                }
            } else {
                setUser(null);
                setUserData(null);
                setView('login');
            }
            setAuthReady(true);
        });
        
        const performInitialSignIn = async () => {
            try {
                if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token) {
                    await signInWithCustomToken(auth, __initial_auth_token);
                } else {
                    await signInAnonymously(auth);
                }
            } catch (err) {
                console.error("Error during initial sign-in:", err);
            }
        };
        performInitialSignIn();

        return () => unsubscribe();
    }, []);


    // --- Event Handlers ---
    const handleLogin = async (username, password) => {
        setError('');
        const email = username.toLowerCase().includes('@') ? username.toLowerCase() : `${username.toLowerCase()}@keadilan.local`;
        try {
            if (username.toLowerCase() === 'novinthen@gmail.com' && password === '123456789') {
                const adminEmail = 'admin@keadilan.local';
                try {
                    await signInWithEmailAndPassword(auth, adminEmail, password);
                } catch (error) {
                    if (error.code === 'auth/user-not-found') {
                       const userCredential = await createUserWithEmailAndPassword(auth, adminEmail, password);
                       const adminUid = userCredential.user.uid;
                       await setDoc(doc(db, `artifacts/${appId}/users`, adminUid), {
                           username: 'admin', role: 'Admin', cabang: 'HQ', isAdmin: true, createdAt: serverTimestamp(), lastLogin: null
                       });
                    } else { throw error; }
                }
                return;
            }
            await signInWithEmailAndPassword(auth, email, password);
        } catch (error) {
            console.error("Login Error:", error);
            if (error.code === 'auth/user-not-found' || error.code === 'auth/wrong-password' || error.code === 'auth/invalid-credential') {
                setError('Invalid username or password.');
            } else {
                setError('An error occurred during login. Please try again.');
            }
        }
    };

    const handleLogout = async () => {
        await logUserActivity(user.uid, 'LOGOUT');
        await signOut(auth);
    };

    // --- Render Logic ---
    if (!authReady) {
        return <div className="flex items-center justify-center h-screen bg-gray-900 text-white"><div className="animate-spin rounded-full h-32 w-32 border-t-2 border-b-2 border-blue-500"></div></div>;
    }

    return (
        <div className="min-h-screen bg-gray-800 text-gray-100 font-sans">
            {view === 'login' && <LoginScreen onLogin={handleLogin} error={error} />}
            {view === 'dashboard' && userData && <UserDashboard user={user} userData={userData} onLogout={handleLogout} />}
            {view === 'admin' && userData && <AdminDashboard onLogout={handleLogout} />}
        </div>
    );
}

// --- Screens and Components ---

function LoginScreen({ onLogin, error }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        onLogin(username, password);
    };

    const handlePasswordReset = async () => {
        const userIdentifier = prompt("Please enter your username (e.g., KC_KEPONG) to receive a password reset link.");
        if (!userIdentifier) return;

        const email = `${userIdentifier.toLowerCase()}@keadilan.local`;
        try {
            await sendPasswordResetEmail(auth, email);
            alert("If an account with that username exists, a password reset link has been sent to the associated email address.");
        } catch (error) {
            console.error("Password Reset Error:", error);
            alert("Could not send password reset email. Please check the username and try again.");
        }
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gray-900">
            <div className="w-full max-w-md p-8 space-y-6 bg-gray-800 rounded-xl shadow-lg">
                <h1 className="text-3xl font-bold text-center text-white">Keadilan WP Info</h1>
                <p className="text-center text-gray-400">Secure Portal</p>
                <form onSubmit={handleSubmit} className="space-y-6">
                    {/* Inputs remain the same */}
                    <div>
                        <label className="block mb-2 text-sm font-medium text-gray-300">Username</label>
                        <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g., KC_KEPONG or admin email" className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required />
                    </div>
                    <div>
                        <label className="block mb-2 text-sm font-medium text-gray-300">Password</label>
                        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" required />
                    </div>
                    {error && <p className="text-sm text-center text-red-400">{error}</p>}
                    <button type="submit" className="w-full px-4 py-2 font-bold text-white bg-blue-600 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-gray-800 focus:ring-blue-500 transition-colors">Login</button>
                </form>
                <div className="text-center">
                    <button onClick={handlePasswordReset} className="text-sm text-blue-400 hover:underline">Forgot Password?</button>
                </div>
            </div>
        </div>
    );
}

function UserDashboard({ user, userData, onLogout }) {
    const [latestNews, setLatestNews] = useState(null);
    const [statement, setStatement] = useState(null);
    const [archive, setArchive] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showArchive, setShowArchive] = useState(false);

    useEffect(() => {
        const newsQuery = query(collection(db, `artifacts/${appId}/public/data/news`));
        const unsubscribeNews = onSnapshot(newsQuery, (querySnapshot) => {
            const newsItems = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            const sortedNews = newsItems.sort((a, b) => b.createdAt?.toMillis() - a.createdAt?.toMillis());
            setLatestNews(sortedNews[0] || null);
            setArchive(sortedNews);
            setLoading(false);
        });
        return () => unsubscribeNews();
    }, []);

    useEffect(() => {
        if (latestNews && user) {
            const statementRef = doc(db, `artifacts/${appId}/public/data/news/${latestNews.id}/statements`, user.uid);
            const unsubscribeStatement = onSnapshot(statementRef, (docSnap) => {
                setStatement(docSnap.exists() ? docSnap.data() : null);
            });
            return () => unsubscribeStatement();
        }
    }, [latestNews, user]);

    const copyToClipboard = (text, newsId) => {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            alert('Statement copied to clipboard!');
            logUserActivity(user.uid, 'COPY_STATEMENT', { newsId: newsId, statementContent: text });
        } catch (err) {
            alert('Failed to copy text.');
        }
        document.body.removeChild(textArea);
    };

    if (loading) {
        return <div className="flex items-center justify-center h-screen bg-gray-900 text-white">Loading Dashboard...</div>;
    }
    
    const renderContent = (newsItem) => (
        <div key={newsItem.id} className="bg-gray-800 p-6 rounded-lg shadow-md mb-6">
            <h2 className="text-2xl font-bold text-blue-400 mb-2">{newsItem.title}</h2>
            <p className="text-gray-300 whitespace-pre-wrap mb-4">{newsItem.content}</p>
            <div className="bg-gray-700 p-4 rounded-lg mt-4">
                <h3 className="text-lg font-semibold text-yellow-400 mb-2">Your Assigned Statement:</h3>
                {statement && statement.newsId === newsItem.id ? (
                    <>
                        <p className="text-gray-200 whitespace-pre-wrap">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="mt-4 px-4 py-2 bg-green-600 hover:bg-green-700 rounded-md font-semibold transition-colors"
                        >
                            Copy Statement
                        </button>
                    </>
                ) : (
                    <p className="text-gray-400">No statement has been assigned for this news item yet.</p>
                )}
            </div>
        </div>
    );

    return (
        <div className="p-4 md:p-8">
            <header className="flex justify-between items-center mb-8">
                <div>
                    <h1 className="text-3xl font-bold text-white">Welcome, {userData.username}</h1>
                    <p className="text-gray-400">{userData.role} - {userData.cabang}</p>
                </div>
                <div>
                     <button onClick={() => setShowArchive(!showArchive)} className="mr-4 px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-md font-semibold transition-colors">
                        {showArchive ? 'View Latest' : 'View Archive'}
                    </button>
                    <button onClick={onLogout} className="px-4 py-2 bg-red-600 hover:bg-red-700 rounded-md font-semibold transition-colors">
                        Logout
                    </button>
                </div>
            </header>
            <main>
                {!showArchive ? (
                    latestNews ? (
                        <>
                            <h2 className="text-2xl font-semibold text-gray-300 border-b-2 border-gray-700 pb-2 mb-4">Latest News & Task</h2>
                            {renderContent(latestNews)}
                        </>
                    ) : (
                        <p className="text-center text-gray-400 mt-10">No news available at the moment.</p>
                    )
                ) : (
                    <>
                        <h2 className="text-2xl font-semibold text-gray-300 border-b-2 border-gray-700 pb-2 mb-4">Archived News</h2>
                        {archive.length > 0 ? (
                            archive.map(item => <ArchivedItem key={item.id} newsItem={item} userId={user.uid} copyToClipboard={copyToClipboard} />)
                        ) : (
                            <p className="text-center text-gray-400 mt-10">The archive is empty.</p>
                        )}
                    </>
                )}
            </main>
        </div>
    );
}

function ArchivedItem({ newsItem, userId, copyToClipboard }) {
    const [statement, setStatement] = useState(null);

    useEffect(() => {
        const statementRef = doc(db, `artifacts/${appId}/public/data/news/${newsItem.id}/statements`, userId);
        const unsubscribe = onSnapshot(statementRef, (docSnap) => {
            setStatement(docSnap.exists() ? docSnap.data() : null);
        });
        return () => unsubscribe();
    }, [newsItem.id, userId]);

    return (
        <div className="bg-gray-800 p-6 rounded-lg shadow-md mb-6">
            <h3 className="text-xl font-bold text-blue-400 mb-2">{newsItem.title}</h3>
            <p className="text-gray-400 text-sm mb-2">Published on: {newsItem.createdAt?.toDate().toLocaleDateString()}</p>
            <p className="text-gray-300 whitespace-pre-wrap mb-4">{newsItem.content}</p>
            <div className="bg-gray-700 p-4 rounded-lg mt-4">
                <h4 className="text-md font-semibold text-yellow-400 mb-2">Your Assigned Statement:</h4>
                {statement ? (
                    <>
                        <p className="text-gray-200 whitespace-pre-wrap">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="mt-4 px-3 py-1 bg-green-600 hover:bg-green-700 rounded-md font-semibold text-sm transition-colors"
                        >
                            Copy
                        </button>
                    </>
                ) : (
                    <p className="text-gray-400">No statement was assigned.</p>
                )}
            </div>
        </div>
    );
}

function AdminDashboard({ onLogout }) {
    const [adminView, setAdminView] = useState('users'); // users, news, activity

    return (
        <div className="flex h-screen">
            <nav className="w-64 bg-gray-900 p-4 flex flex-col">
                <h1 className="text-2xl font-bold text-white mb-8">Admin Panel</h1>
                <button onClick={() => setAdminView('users')} className={`w-full text-left p-3 rounded-md mb-2 ${adminView === 'users' ? 'bg-blue-600' : 'hover:bg-gray-700'}`}>User Management</button>
                <button onClick={() => setAdminView('news')} className={`w-full text-left p-3 rounded-md mb-2 ${adminView === 'news' ? 'bg-blue-600' : 'hover:bg-gray-700'}`}>News & Statements</button>
                <button onClick={() => setAdminView('activity')} className={`w-full text-left p-3 rounded-md mb-2 ${adminView === 'activity' ? 'bg-blue-600' : 'hover:bg-gray-700'}`}>User Activity</button>
                <div className="mt-auto">
                    <button onClick={onLogout} className="w-full p-3 rounded-md bg-red-600 hover:bg-red-700 font-bold">Logout</button>
                </div>
            </nav>
            <main className="flex-1 p-8 bg-gray-800 overflow-y-auto">
                {adminView === 'users' && <UserManagement />}
                {adminView === 'news' && <NewsManagement />}
                {adminView === 'activity' && <UserActivityLog />}
            </main>
        </div>
    );
}

function UserManagement() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const usersQuery = query(collection(db, `artifacts/${appId}/users`), where("isAdmin", "!=", true));
        const unsubscribe = onSnapshot(usersQuery, (snapshot) => {
            setUsers(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    const handleCreateUsers = async () => {
        if (!window.confirm("This will create accounts for all predefined roles and cabangs. Passwords will match usernames (e.g., KC_KEPONG). Are you sure?")) return;
        alert("Starting user creation...");
        let createdCount = 0;
        for (const cabang of CABANGS) {
            for (const role of ROLES) {
                const username = `${role}_${cabang}`;
                const password = username;
                const email = `${username.toLowerCase()}@keadilan.local`;
                try {
                    const userQuery = query(collection(db, `artifacts/${appId}/users`), where("username", "==", username));
                    if ((await getDocs(userQuery)).empty) {
                        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
                        await setDoc(doc(db, `artifacts/${appId}/users`, userCredential.user.uid), {
                            username, role, cabang, isAdmin: false, createdAt: serverTimestamp(), lastLogin: null
                        });
                        createdCount++;
                    }
                } catch (error) { console.error(`Failed to create user ${username}:`, error); }
            }
        }
        alert(`${createdCount} new users created successfully!`);
    };

    const handleAdminPasswordReset = async (username) => {
        if (!window.confirm(`Are you sure you want to send a password reset link to ${username}?`)) return;
        const email = `${username.toLowerCase()}@keadilan.local`;
        try {
            await sendPasswordResetEmail(auth, email);
            alert(`Password reset link sent for ${username}.`);
        } catch (error) {
            alert(`Failed to send reset link for ${username}.`);
            console.error(error);
        }
    };
    
    if (loading) return <div>Loading users...</div>;

    return (
        <div>
            <h2 className="text-3xl font-bold mb-6">User Management</h2>
            <button onClick={handleCreateUsers} className="mb-6 px-4 py-2 bg-green-600 hover:bg-green-700 rounded-md font-bold">Bulk Create All WP Users</button>
            <div className="bg-gray-900 p-4 rounded-lg">
                <table className="w-full text-left">
                    <thead>
                        <tr className="border-b border-gray-700">
                            <th className="p-3">Username</th><th className="p-3">Role</th><th className="p-3">Cabang</th><th className="p-3">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id} className="border-b border-gray-800 hover:bg-gray-800">
                                <td className="p-3">{user.username}</td><td className="p-3">{user.role}</td><td className="p-3">{user.cabang}</td>
                                <td className="p-3">
                                    <button onClick={() => handleAdminPasswordReset(user.username)} className="px-3 py-1 bg-yellow-600 hover:bg-yellow-700 text-white text-sm rounded">Reset Pass</button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function NewsManagement() {
    // This component remains largely the same as before
    const [newsItems, setNewsItems] = useState([]);
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [selectedNewsId, setSelectedNewsId] = useState(null);

    useEffect(() => {
        const newsQuery = query(collection(db, `artifacts/${appId}/public/data/news`));
        const unsubscribe = onSnapshot(newsQuery, (snapshot) => {
            const items = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setNewsItems(items.sort((a,b) => b.createdAt?.toMillis() - a.createdAt?.toMillis()));
        });
        return () => unsubscribe();
    }, []);

    const handlePublishNews = async (e) => {
        e.preventDefault();
        if (!title || !content) {
            alert("Title and content are required.");
            return;
        }
        try {
            await addDoc(collection(db, `artifacts/${appId}/public/data/news`), {
                title, content, createdAt: serverTimestamp(), archived: false
            });
            setTitle(''); setContent('');
            alert("News published successfully!");
        } catch (error) {
            console.error("Error publishing news:", error);
            alert("Failed to publish news.");
        }
    };

    return (
        <div>
            <h2 className="text-3xl font-bold mb-6">News & Statements</h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
                <div className="bg-gray-900 p-6 rounded-lg">
                    <h3 className="text-xl font-bold mb-4">Publish New Article</h3>
                    <form onSubmit={handlePublishNews} className="space-y-4">
                        <input type="text" value={title} onChange={e => setTitle(e.target.value)} placeholder="News Title" className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
                        <textarea value={content} onChange={e => setContent(e.target.value)} placeholder="News content..." rows="6" className="w-full px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"></textarea>
                        <button type="submit" className="w-full px-4 py-2 font-bold text-white bg-blue-600 rounded-md hover:bg-blue-700">Publish News</button>
                    </form>
                </div>
                <div className="bg-gray-900 p-6 rounded-lg">
                    <h3 className="text-xl font-bold mb-4">Assign Statements</h3>
                     <div className="max-h-96 overflow-y-auto">
                        {newsItems.map(item => (
                            <div key={item.id} onClick={() => setSelectedNewsId(item.id)} className={`p-3 rounded-md mb-2 cursor-pointer ${selectedNewsId === item.id ? 'bg-blue-800' : 'bg-gray-800 hover:bg-gray-700'}`}>
                                <p className="font-semibold">{item.title}</p>
                                <p className="text-sm text-gray-400">{item.createdAt?.toDate().toLocaleDateString()}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
            {selectedNewsId && <StatementAssigner newsId={selectedNewsId} />}
        </div>
    );
}

function StatementAssigner({ newsId }) {
    // This component remains largely the same
    const [users, setUsers] = useState([]);
    const [statements, setStatements] = useState({});

    useEffect(() => {
        const usersQuery = query(collection(db, `artifacts/${appId}/users`), where("isAdmin", "!=", true));
        getDocs(usersQuery).then(snapshot => setUsers(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))));
        
        const statementsCollection = collection(db, `artifacts/${appId}/public/data/news/${newsId}/statements`);
        getDocs(statementsCollection).then(snapshot => {
            const existing = {};
            snapshot.forEach(doc => { existing[doc.id] = doc.data().content; });
            setStatements(existing);
        });
    }, [newsId]);

    const handleStatementChange = (userId, value) => setStatements(prev => ({ ...prev, [userId]: value }));

    const handleSaveStatements = async () => {
        if (!window.confirm("Save or update all statements for this news item?")) return;
        alert("Saving statements...");
        let successCount = 0;
        for (const userId in statements) {
            if (statements[userId]) {
                try {
                    await setDoc(doc(db, `artifacts/${appId}/public/data/news/${newsId}/statements`, userId), {
                        content: statements[userId], newsId, assignedAt: serverTimestamp()
                    });
                    successCount++;
                } catch (error) { console.error(`Failed to save for user ${userId}:`, error); }
            }
        }
        alert(`${successCount} statements saved successfully!`);
    };

    return (
        <div className="mt-8 bg-gray-900 p-6 rounded-lg">
            <h3 className="text-xl font-bold mb-4">Assign Statements for Selected News</h3>
            <div className="space-y-4 max-h-[60vh] overflow-y-auto pr-4">
                {users.map(user => (
                    <div key={user.id}>
                        <label className="block text-sm font-medium text-gray-300">{user.username} ({user.role})</label>
                        <textarea value={statements[user.id] || ''} onChange={e => handleStatementChange(user.id, e.target.value)} placeholder={`Enter unique statement for ${user.username}...`} rows="2" className="w-full mt-1 px-4 py-2 bg-gray-700 border border-gray-600 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" />
                    </div>
                ))}
            </div>
            <button onClick={handleSaveStatements} className="mt-6 w-full px-4 py-2 font-bold text-white bg-green-600 rounded-md hover:bg-green-700">Save All Statements</button>
        </div>
    );
}

function UserActivityLog() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        const usersQuery = query(collection(db, `artifacts/${appId}/users`), where("isAdmin", "!=", true));
        const unsubscribe = onSnapshot(usersQuery, (snapshot) => {
            const userList = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setUsers(userList.sort((a,b) => (b.lastLogin?.toMillis() || 0) - (a.lastLogin?.toMillis() || 0)));
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    if (loading) return <div>Loading activity logs...</div>;

    if (selectedUser) {
        return <DetailedActivityView user={selectedUser} onBack={() => setSelectedUser(null)} />;
    }

    return (
        <div>
            <h2 className="text-3xl font-bold mb-6">User Activity Overview</h2>
            <div className="bg-gray-900 p-4 rounded-lg">
                <table className="w-full text-left">
                    <thead>
                         <tr className="border-b border-gray-700">
                            <th className="p-3">Username</th><th className="p-3">Last Login</th><th className="p-3">IP Address (Demo)</th><th className="p-3">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id} className="border-b border-gray-800 hover:bg-gray-700 cursor-pointer" onClick={() => setSelectedUser(user)}>
                                <td className="p-3">{user.username}</td>
                                <td className="p-3">{user.lastLogin ? user.lastLogin.toDate().toLocaleString() : 'Never'}</td>
                                <td className="p-3">{user.ipAddress || 'N/A'}</td>
                                <td className="p-3 text-blue-400 hover:underline">View Log</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

function DetailedActivityView({ user, onBack }) {
    const [log, setLog] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const logQuery = query(collection(db, `artifacts/${appId}/users/${user.id}/activityLog`));
        const unsubscribe = onSnapshot(logQuery, (snapshot) => {
            const logData = snapshot.docs.map(doc => ({id: doc.id, ...doc.data()}));
            setLog(logData.sort((a,b) => b.timestamp?.toMillis() - a.timestamp?.toMillis()));
            setLoading(false);
        });
        return () => unsubscribe();
    }, [user.id]);

    if (loading) return <div>Loading detailed log...</div>;

    return (
        <div>
            <button onClick={onBack} className="mb-6 px-4 py-2 bg-gray-600 hover:bg-gray-700 rounded-md font-bold">&larr; Back to Overview</button>
            <h2 className="text-3xl font-bold mb-2">Activity Log for {user.username}</h2>
            <p className="text-gray-400 mb-6">{user.role} - {user.cabang}</p>
             <div className="bg-gray-900 p-4 rounded-lg">
                <table className="w-full text-left">
                    <thead>
                         <tr className="border-b border-gray-700">
                            <th className="p-3">Timestamp</th><th className="p-3">Event Type</th><th className="p-3">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log.map(entry => (
                            <tr key={entry.id} className="border-b border-gray-800">
                                <td className="p-3">{entry.timestamp ? entry.timestamp.toDate().toLocaleString() : '...'}</td>
                                <td className="p-3"><span className={`px-2 py-1 text-xs font-semibold rounded-full ${entry.type === 'LOGIN_SUCCESS' ? 'bg-green-500 text-green-900' : entry.type === 'LOGOUT' ? 'bg-red-500 text-red-900' : 'bg-yellow-500 text-yellow-900'}`}>{entry.type}</span></td>
                                <td className="p-3 text-sm text-gray-400">{entry.newsId ? `News ID: ${entry.newsId.substring(0,10)}...` : entry.ipAddress || ''}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
