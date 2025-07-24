import React, { useState, useEffect } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut, signInAnonymously, signInWithCustomToken, sendPasswordResetEmail } from 'firebase/auth';
import { getFirestore, doc, getDoc, setDoc, addDoc, collection, onSnapshot, query, where, getDocs, updateDoc, serverTimestamp } from 'firebase/firestore';
import { setLogLevel } from 'firebase/firestore';

// --- Helper Functions & Initial Config ---

// This new block correctly handles configuration for both Vercel and local development.
let firebaseConfig;

try {
    if (process.env.REACT_APP_FIREBASE_CONFIG) {
      // Use the environment variable on Vercel
      firebaseConfig = JSON.parse(process.env.REACT_APP_FIREBASE_CONFIG);
      // eslint-disable-next-line no-undef
    } else if (typeof __firebase_config !== 'undefined') {
      // Use the config from the immersive environment
      // eslint-disable-next-line no-undef
      firebaseConfig = JSON.parse(__firebase_config);
    } else {
      // Fallback for local development if no environment variable is set
      console.warn("Firebase config not found in environment variables. This is expected for local development but will fail if deployed.");
      firebaseConfig = { apiKey: "INVALID_KEY" }; // Intentionally invalid to fail fast
    }
} catch (e) {
    console.error("Could not parse Firebase config:", e);
    firebaseConfig = { apiKey: "INVALID_KEY" }; // Fail gracefully
}


// Initialize Firebase
const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
setLogLevel('debug'); // For detailed console logs

// App ID - crucial for Firestore paths
// eslint-disable-next-line no-undef
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
function AppContainer() {
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
                // eslint-disable-next-line no-undef
                if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token) {
                    // eslint-disable-next-line no-undef
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
        try {
            if (username.toLowerCase() === 'novinthen@gmail.com' && password === '123456789') {
                const adminEmail = 'admin@keadilan.local';
                try {
                    await signInWithEmailAndPassword(auth, adminEmail, password);
                } catch (error) {
                    if (error.code === 'auth/user-not-found') {
                        try {
                            const userCredential = await createUserWithEmailAndPassword(auth, adminEmail, password);
                            const adminUid = userCredential.user.uid;
                            await setDoc(doc(db, `artifacts/${appId}/users`, adminUid), {
                                username: 'admin', role: 'Admin', cabang: 'HQ', isAdmin: true, createdAt: serverTimestamp(), lastLogin: null
                            });
                        } catch (creationError) {
                            console.error("Admin user creation failed:", creationError);
                            setError(`Admin setup failed: ${creationError.code}`);
                        }
                    } else {
                        throw error;
                    }
                }
            } else {
                const email = username.toLowerCase().includes('@') ? username.toLowerCase() : `${username.toLowerCase()}@keadilan.local`;
                await signInWithEmailAndPassword(auth, email, password);
            }
        } catch (error) {
            console.error("Login Error:", error);
            console.log("Firebase Error Code:", error.code); // For debugging
            if (error.code === 'auth/api-key-not-valid') {
                setError('Configuration error: Invalid API Key. Please contact support.');
            } else if (error.code === 'auth/wrong-password' || error.code === 'auth/invalid-credential') {
                setError('Invalid username or password.');
            } else if (error.code === 'auth/user-not-found') {
                setError('User does not exist. Please contact admin.');
            } else {
                // Display the actual error code to the user for diagnosis
                setError(`Login failed with error: ${error.code}`);
            }
        }
    };

    const handleLogout = async () => {
        if (user) {
            await logUserActivity(user.uid, 'LOGOUT');
        }
        await signOut(auth);
    };

    // --- Render Logic ---
    if (!authReady) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="animate-spin rounded-full h-32 w-32 border-t-2 border-b-2 border-white"></div>
            </div>
        );
    }

    // Main view rendering
    let currentView;
    switch (view) {
        case 'dashboard':
            currentView = <UserDashboard user={user} userData={userData} onLogout={handleLogout} />;
            break;
        case 'admin':
            currentView = <AdminDashboard onLogout={handleLogout} />;
            break;
        case 'login':
        default:
            currentView = <LoginScreen onLogin={handleLogin} error={error} />;
    }

    return (
        <div className="w-full h-full flex flex-col items-center justify-center">
            {currentView}
        </div>
    );
}

// --- Screens and Components with new Glassmorphism Style ---

function LoginScreen({ onLogin, error }) {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');

    const handleSubmit = (e) => {
        e.preventDefault();
        onLogin(username, password);
    };
    
    return (
        <div className="w-full max-w-md p-8 md:p-10 space-y-6 bg-black/20 backdrop-blur-xl border border-white/20 rounded-3xl shadow-2xl">
            <h2 className="text-4xl font-bold text-center text-white">Keadilan WP Info</h2>
            <p className="text-center text-gray-200">Secure Portal</p>
            <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                    <label className="block mb-2 text-lg font-medium text-gray-200">Username</label>
                    <input type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="e.g., KC_KEPONG" className="w-full px-5 py-3 text-lg bg-white/10 border border-white/20 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#00AEEF] text-white" required />
                </div>
                <div>
                    <label className="block mb-2 text-lg font-medium text-gray-200">Password</label>
                    <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" className="w-full px-5 py-3 text-lg bg-white/10 border border-white/20 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#00AEEF] text-white" required />
                </div>
                {error && <p className="text-md text-center text-red-400 bg-red-900/50 p-3 rounded-xl">{error}</p>}
                <button type="submit" className="w-full px-5 py-4 text-xl font-bold text-white bg-[#0033A0] rounded-xl hover:bg-[#00AEEF] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-black/20 focus:ring-white transition-all duration-300">
                    Login
                </button>
            </form>
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
        return <div className="text-white text-2xl">Loading Dashboard...</div>;
    }
    
    const renderContent = (newsItem, isArchived = false) => (
        <div key={newsItem.id} className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-3xl shadow-2xl p-6 md:p-8 mb-8">
            <h2 className="text-3xl font-bold text-white mb-2">{newsItem.title}</h2>
             {isArchived && <p className="text-gray-300 text-sm mb-4">Published on: {newsItem.createdAt?.toDate().toLocaleDateString()}</p>}
            <p className="text-gray-200 whitespace-pre-wrap mb-6 text-lg">{newsItem.content}</p>
            <div className="bg-black/20 p-6 rounded-2xl mt-4">
                <h3 className="text-2xl font-semibold text-white mb-3">Your Assigned Statement:</h3>
                {statement && statement.newsId === newsItem.id ? (
                    <>
                        <p className="text-gray-100 whitespace-pre-wrap text-lg">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="mt-6 px-6 py-3 bg-[#00AEEF] hover:bg-[#0033A0] rounded-xl font-semibold transition-all duration-300"
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
        <div className="w-full max-w-5xl p-4 md:p-0">
            <header className="flex flex-col md:flex-row justify-between items-center mb-10 text-white">
                <div className="text-center md:text-left mb-4 md:mb-0">
                    <h1 className="text-4xl font-bold">Welcome, {userData.username}</h1>
                    <p className="text-xl text-gray-300">{userData.role} - {userData.cabang}</p>
                </div>
                <div className="flex items-center space-x-4">
                     <button onClick={() => setShowArchive(!showArchive)} className="px-5 py-3 bg-white/10 hover:bg-white/20 rounded-xl font-semibold transition-colors">
                        {showArchive ? 'View Latest' : 'View Archive'}
                    </button>
                    <button onClick={onLogout} className="px-5 py-3 bg-[#ED1C24]/80 hover:bg-[#ED1C24] rounded-xl font-semibold transition-colors">
                        Logout
                    </button>
                </div>
            </header>
            <main>
                {!showArchive ? (
                    latestNews ? (
                        <>
                            <h2 className="text-3xl font-semibold text-white border-b-2 border-white/20 pb-3 mb-6">Latest News & Task</h2>
                            {renderContent(latestNews)}
                        </>
                    ) : (
                        <div className="text-center text-gray-300 mt-10 text-2xl p-10 bg-black/20 rounded-3xl">No news available.</div>
                    )
                ) : (
                    <>
                        <h2 className="text-3xl font-semibold text-white border-b-2 border-white/20 pb-3 mb-6">Archived News</h2>
                        {archive.length > 0 ? (
                            archive.map(item => <ArchivedItem key={item.id} newsItem={item} userId={user.uid} copyToClipboard={copyToClipboard} />)
                        ) : (
                            <div className="text-center text-gray-300 mt-10 text-2xl p-10 bg-black/20 rounded-3xl">The archive is empty.</div>
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
        <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-3xl shadow-2xl p-6 md:p-8 mb-8">
            <h3 className="text-2xl font-bold text-white mb-2">{newsItem.title}</h3>
            <p className="text-gray-300 text-sm mb-4">Published on: {newsItem.createdAt?.toDate().toLocaleDateString()}</p>
            <div className="bg-black/20 p-6 rounded-2xl mt-4">
                <h4 className="text-xl font-semibold text-white mb-2">Your Assigned Statement:</h4>
                {statement ? (
                    <>
                        <p className="text-gray-100 whitespace-pre-wrap text-lg">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="mt-4 px-5 py-2 bg-[#00AEEF] hover:bg-[#0033A0] rounded-xl font-semibold text-md transition-all duration-300"
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
        <div className="flex h-screen w-full">
            <nav className="w-72 bg-black/30 backdrop-blur-xl border-r border-white/20 p-6 flex flex-col">
                <h1 className="text-3xl font-bold text-white mb-12">Admin Panel</h1>
                <button onClick={() => setAdminView('users')} className={`w-full text-left p-4 rounded-xl mb-3 text-lg transition-all ${adminView === 'users' ? 'bg-[#00AEEF] text-white' : 'hover:bg-white/10'}`}>User Management</button>
                <button onClick={() => setAdminView('news')} className={`w-full text-left p-4 rounded-xl mb-3 text-lg transition-all ${adminView === 'news' ? 'bg-[#00AEEF] text-white' : 'hover:bg-white/10'}`}>News & Statements</button>
                <button onClick={() => setAdminView('activity')} className={`w-full text-left p-4 rounded-xl mb-3 text-lg transition-all ${adminView === 'activity' ? 'bg-[#00AEEF] text-white' : 'hover:bg-white/10'}`}>User Activity</button>
                <div className="mt-auto">
                    <button onClick={onLogout} className="w-full p-4 rounded-xl bg-[#ED1C24]/80 hover:bg-[#ED1C24] font-bold text-lg">Logout</button>
                </div>
            </nav>
            <main className="flex-1 p-10 overflow-y-auto">
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
    
    if (loading) return <div className="text-white text-xl">Loading users...</div>;

    return (
        <div>
            <h2 className="text-4xl font-bold mb-8 text-white">User Management</h2>
            <button onClick={handleCreateUsers} className="mb-8 px-6 py-3 bg-green-600 hover:bg-green-700 rounded-xl font-bold text-lg">
                Bulk Create All WP Users
            </button>
            <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
                <table className="w-full text-left text-lg">
                    <thead>
                        <tr className="border-b border-white/20">
                            <th className="p-4">Username</th><th className="p-4">Role</th><th className="p-4">Cabang</th><th className="p-4">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id} className="border-b border-white/10 hover:bg-white/5">
                                <td className="p-4">{user.username}</td><td className="p-4">{user.role}</td><td className="p-4">{user.cabang}</td>
                                <td className="p-4">
                                    <button onClick={() => handleAdminPasswordReset(user.username)} className="px-4 py-2 bg-yellow-600 hover:bg-yellow-700 text-white text-md rounded-lg">Reset Pass</button>
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
            <h2 className="text-4xl font-bold mb-8 text-white">News & Statements</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-8">
                    <h3 className="text-2xl font-bold mb-4">Publish New Article</h3>
                    <form onSubmit={handlePublishNews} className="space-y-4">
                        <input type="text" value={title} onChange={e => setTitle(e.target.value)} placeholder="News Title" className="w-full text-lg px-5 py-3 bg-white/10 border border-white/20 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#00AEEF] text-white" />
                        <textarea value={content} onChange={e => setContent(e.target.value)} placeholder="News content..." rows="6" className="w-full text-lg px-5 py-3 bg-white/10 border border-white/20 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#00AEEF] text-white"></textarea>
                        <button type="submit" className="w-full py-3 text-xl font-bold text-white bg-[#0033A0] rounded-xl hover:bg-[#00AEEF] transition-all duration-300">Publish News</button>
                    </form>
                </div>
                <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-8">
                    <h3 className="text-2xl font-bold mb-4">Assign Statements</h3>
                     <div className="max-h-96 overflow-y-auto pr-2">
                        {newsItems.map(item => (
                            <div key={item.id} onClick={() => setSelectedNewsId(item.id)} className={`p-4 rounded-xl mb-2 cursor-pointer transition-all ${selectedNewsId === item.id ? 'bg-[#00AEEF]' : 'bg-white/5 hover:bg-white/10'}`}>
                                <p className="font-semibold text-lg">{item.title}</p>
                                <p className="text-sm text-gray-300">{item.createdAt?.toDate().toLocaleDateString()}</p>
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
        <div className="mt-8 bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-8">
            <h3 className="text-2xl font-bold mb-6">Assign Statements for Selected News</h3>
            <div className="space-y-4 max-h-[50vh] overflow-y-auto pr-4">
                {users.map(user => (
                    <div key={user.id}>
                        <label className="block text-md font-medium text-gray-200">{user.username} ({user.role})</label>
                        <textarea value={statements[user.id] || ''} onChange={e => handleStatementChange(user.id, e.target.value)} placeholder={`Enter unique statement for ${user.username}...`} rows="2" className="w-full mt-1 text-lg px-5 py-3 bg-white/10 border border-white/20 rounded-xl focus:outline-none focus:ring-2 focus:ring-[#00AEEF] text-white" />
                    </div>
                ))}
            </div>
            <button onClick={handleSaveStatements} className="mt-6 w-full py-3 text-xl font-bold text-white bg-green-600 rounded-xl hover:bg-green-700 transition-all">Save All Statements</button>
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

    if (loading) return <div className="text-white text-xl">Loading activity logs...</div>;

    if (selectedUser) {
        return <DetailedActivityView user={selectedUser} onBack={() => setSelectedUser(null)} />;
    }

    return (
        <div>
            <h2 className="text-4xl font-bold mb-8 text-white">User Activity Overview</h2>
            <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
                <table className="w-full text-left text-lg">
                    <thead>
                         <tr className="border-b border-white/20">
                            <th className="p-4">Username</th><th className="p-4">Last Login</th><th className="p-4">IP Address (Demo)</th><th className="p-4">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map(user => (
                            <tr key={user.id} className="border-b border-white/10 hover:bg-white/5 cursor-pointer" onClick={() => setSelectedUser(user)}>
                                <td className="p-4">{user.username}</td>
                                <td className="p-4">{user.lastLogin ? user.lastLogin.toDate().toLocaleString() : 'Never'}</td>
                                <td className="p-4">{user.ipAddress || 'N/A'}</td>
                                <td className="p-4 text-[#00AEEF] hover:underline">View Log</td>
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

    if (loading) return <div className="text-white text-xl">Loading detailed log...</div>;

    return (
        <div>
            <button onClick={onBack} className="mb-8 px-5 py-2 bg-white/10 hover:bg-white/20 rounded-xl font-bold">&larr; Back to Overview</button>
            <h2 className="text-4xl font-bold mb-2 text-white">Activity Log for {user.username}</h2>
            <p className="text-gray-300 mb-8 text-xl">{user.role} - {user.cabang}</p>
             <div className="bg-black/20 backdrop-blur-xl border border-white/20 rounded-2xl p-6">
                <table className="w-full text-left text-lg">
                    <thead>
                         <tr className="border-b border-white/20">
                            <th className="p-4">Timestamp</th><th className="p-4">Event Type</th><th className="p-4">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log.map(entry => (
                            <tr key={entry.id} className="border-b border-white/10">
                                <td className="p-4">{entry.timestamp ? entry.timestamp.toDate().toLocaleString() : '...'}</td>
                                <td className="p-4"><span className={`px-3 py-1 text-sm font-semibold rounded-full ${entry.type === 'LOGIN_SUCCESS' ? 'bg-green-500 text-green-900' : entry.type === 'LOGOUT' ? 'bg-red-500 text-red-900' : 'bg-yellow-500 text-yellow-900'}`}>{entry.type}</span></td>
                                <td className="p-4 text-gray-300">{entry.newsId ? `News ID: ${entry.newsId.substring(0,10)}...` : entry.ipAddress || ''}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// This is the new root component that applies the background and overall layout
export default function Root() {
    return (
        <div className="min-h-screen w-full bg-gradient-to-br from-[#0033A0] to-[#00AEEF] text-white font-sans flex flex-col items-center p-4 sm:p-6 lg:p-8">
            <h1 className="text-5xl font-bold text-white my-8 text-center shadow-lg">Keadilan WP Campaign Platform</h1>
            <main className="w-full h-full flex-1 flex flex-col items-center justify-center">
                <AppContainer />
            </main>
            <footer className="w-full text-center py-6 text-gray-300 mt-8">
                ©2025 Sungai Siput
            </footer>
        </div>
    );
}
