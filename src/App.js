import React, { useState, useEffect, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut, signInAnonymously, signInWithCustomToken, sendPasswordResetEmail } from 'firebase/auth';
import { getFirestore, doc, getDoc, setDoc, addDoc, collection, onSnapshot, query, where, getDocs, updateDoc, serverTimestamp, orderBy, limit } from 'firebase/firestore';
import { setLogLevel } from 'firebase/firestore';
import { useForm } from 'react-hook-form';
import * as yup from 'yup';
import { yupResolver } from '@hookform/resolvers/yup';
import { APP_ID, CABANGS, ROLES, PATHS } from './constants';
import './App.css';

// --- Firebase Initialization ---
let firebaseConfig;
try {
    if (process.env.REACT_APP_FIREBASE_CONFIG) {
        firebaseConfig = JSON.parse(process.env.REACT_APP_FIREBASE_CONFIG);
    } else {
        console.warn("Firebase config not found in environment variables. This is expected for local development but will fail if deployed.");
        firebaseConfig = { apiKey: "INVALID_KEY" };
    }
} catch (e) {
    console.error("Could not parse Firebase config:", e);
    firebaseConfig = { apiKey: "INVALID_KEY" };
}

} catch (e) {
    console.error("Could not parse Firebase config:", e);
    firebaseConfig = { apiKey: "INVALID_KEY" };
}

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
setLogLevel('debug');

// --- Helper to log activity ---
const logUserActivity = async (userId, type, details = {}) => {
    if (!userId) return;
    try {
        const logCollectionRef = collection(db, `${PATHS.USERS}/${userId}/activityLog`);
        await addDoc(logCollectionRef, {
            type,
            timestamp: serverTimestamp(),
            ipAddress: '127.0.0.1 (demo)',
            ...details,
        });
    } catch (error) {
        console.error("Error logging activity:", error);
    }
};

// --- Reusable NewsItem Component ---
function NewsItem({ newsItem, userId, copyToClipboard, isArchived = false }) {
    const [statement, setStatement] = useState(null);

    useEffect(() => {
        const statementRef = doc(db, `${PATHS.NEWS}/${newsItem.id}/statements`, userId);
        const unsubscribe = onSnapshot(statementRef, (docSnap) => {
            setStatement(docSnap.exists() ? docSnap.data() : null);
        });
        return () => unsubscribe();
    }, [newsItem.id, userId]);

    return (
        <div className="news-item">
            <h3 className="news-title">{newsItem.title}</h3>
            {isArchived && <p className="news-date">Published: {newsItem.createdAt?.toDate().toLocaleDateString()}</p>}
            <p className="news-content">{newsItem.content}</p>
            <div className="statement-container">
                <h4 className="statement-title">Your Statement:</h4>
                {statement && statement.newsId === newsItem.id ? (
                    <>
                        <p className="statement-content">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="primary-button"
                        >
                            Copy Statement
                        </button>
                    </>
                ) : (
                    <p className="statement-empty">No statement assigned.</p>
                )}
            </div>
        </div>
    );
}

// --- Main App Component ---
function AppContainer() {
    const [user, setUser] = useState(null);
    const [authReady, setAuthReady] = useState(false);
    const [userData, setUserData] = useState(null);
    const [view, setView] = useState('login');
    const [error, setError] = useState('');

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
            if (firebaseUser && !firebaseUser.isAnonymous) {
                const userDocRef = doc(db, PATHS.USERS, firebaseUser.uid);
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

    const handleLogin = useCallback(async (username, password) => {
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
                            await setDoc(doc(db, `${PATHS.USERS}`, adminUid), {
                                username: 'admin', role: 'Admin', cabang: 'HQ', isAdmin: true, createdAt: serverTimestamp(), lastLogin: null
                            });
                        } catch (creationError) {
                            console.error("Admin user creation failed:", creationError);
                            setError(`Admin account setup failed. Error code: ${creationError.code}`);
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
            setError(`Login failed. Error code: ${error.code}`);
        }
    }, []);

    const handleLogout = useCallback(async () => {
        if (user) {
            await logUserActivity(user.uid, 'LOGOUT');
        }
        await signOut(auth);
    }, [user]);

    if (!authReady) {
        return (
            <div className="loading-spinner">
                <div className="spinner"></div>
            </div>
        );
    }

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
        <div className="app-container">
            {currentView}
        </div>
    );
}

// --- Login Screen with Form Validation ---
const schema = yup.object({
    username: yup.string().required('Username is required'),
    password: yup.string().min(6, 'Password must be at least 6 characters').required('Password is required'),
});

function LoginScreen({ onLogin, error }) {
    const { register, handleSubmit, formState: { errors } } = useForm({
        resolver: yupResolver(schema),
    });

    return (
        <div className="login-container">
            <h2 className="login-title">Keadilan WP Info</h2>
            <p className="login-subtitle">Secure Campaign Portal</p>
            <form onSubmit={handleSubmit(({ username, password }) => onLogin(username, password))} className="login-form">
                <div className="form-group">
                    <label className="form-label">Username</label>
                    <input
                        {...register('username')}
                        placeholder="e.g., KC_KEPONG"
                        className="form-input"
                        aria-label="Username"
                    />
                    {errors.username && <p className="form-error">{errors.username.message}</p>}
                </div>
                <div className="form-group">
                    <label className="form-label">Password</label>
                    <input
                        type="password"
                        {...register('password')}
                        placeholder="Password"
                        className="form-input"
                        aria-label="Password"
                    />
                    {errors.password && <p className="form-error">{errors.password.message}</p>}
                </div>
                {error && <p className="error-message">{error}</p>}
                <button
                    type="submit"
                    className="primary-button"
                    aria-label="Login to the platform"
                >
                    Login
                </button>
            </form>
        </div>
    );
}

// --- User Dashboard with Skeleton Loading ---
function UserDashboard({ user, userData, onLogout }) {
    const [latestNews, setLatestNews] = useState(null);
    const [archive, setArchive] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showArchive, setShowArchive] = useState(false);

    useEffect(() => {
        const newsQuery = query(
            collection(db, PATHS.NEWS),
            orderBy('createdAt', 'desc'),
            limit(10)
        );
        const unsubscribeNews = onSnapshot(newsQuery, (querySnapshot) => {
            const newsItems = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setLatestNews(newsItems[0] || null);
            setArchive(newsItems);
            setLoading(false);
        });
        return () => unsubscribeNews();
    }, []);

    const copyToClipboard = useCallback((text, newsId) => {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            alert('Statement copied to clipboard!');
            logUserActivity(user.uid, 'COPY_STATEMENT', { newsId, statementContent: text });
        } catch (err) {
            alert('Failed to copy text.');
        }
        document.body.removeChild(textArea);
    }, [user.uid]);

    if (loading) {
        return (
            <div className="dashboard-container">
                <div className="skeleton skeleton-header pulse"></div>
                <div className="skeleton skeleton-content pulse"></div>
            </div>
        );
    }

    return (
        <div className="dashboard-container">
            <header className="dashboard-header">
                <div>
                    <h1 className="dashboard-title">Welcome, {userData.username}</h1>
                    <p className="dashboard-subtitle">{userData.role} - {userData.cabang}</p>
                </div>
                <div className="header-buttons">
                    <button
                        onClick={() => setShowArchive(!showArchive)}
                        className="secondary-button"
                        aria-label={showArchive ? 'View latest news' : 'View archived news'}
                    >
                        {showArchive ? 'Latest News' : 'View Archive'}
                    </button>
                    <button
                        onClick={onLogout}
                        className="logout-button"
                        aria-label="Logout"
                    >
                        Logout
                    </button>
                </div>
            </header>
            <main>
                {!showArchive ? (
                    latestNews ? (
                        <>
                            <h2 className="section-title">Latest News & Task</h2>
                            <NewsItem newsItem={latestNews} userId={user.uid} copyToClipboard={copyToClipboard} />
                        </>
                    ) : (
                        <div className="empty-message">No news available.</div>
                    )
                ) : (
                    <>
                        <h2 className="section-title">Archived News</h2>
                        {archive.length > 0 ? (
                            archive.map(item => (
                                <NewsItem
                                    key={item.id}
                                    newsItem={item}
                                    userId={user.uid}
                                    copyToClipboard={copyToClipboard}
                                    isArchived={true}
                                />
                            ))
                        ) : (
                            <div className="empty-message">The archive is empty.</div>
                        )}
                    </>
                )}
            </main>
        </div>
    );
}

// --- Admin Dashboard with Responsive Sidebar ---
function AdminDashboard({ onLogout }) {
    const [adminView, setAdminView] = useState('users');
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    return (
        <div className="admin-container">
            <nav className={`admin-sidebar ${isSidebarOpen ? 'open' : ''}`}>
                <button
                    className="sidebar-close"
                    onClick={() => setIsSidebarOpen(false)}
                    aria-label="Close sidebar"
                >
                    ✕
                </button>
                <h1 className="sidebar-title">PKR Admin Panel</h1>
                <button
                    onClick={() => setAdminView('users')}
                    className={`sidebar-button ${adminView === 'users' ? 'active' : ''}`}
                    aria-label="View user management"
                >
                    User Management
                </button>
                <button
                    onClick={() => setAdminView('news')}
                    className={`sidebar-button ${adminView === 'news' ? 'active' : ''}`}
                    aria-label="View news and statements"
                >
                    News & Statements
                </button>
                <button
                    onClick={() => setAdminView('activity')}
                    className={`sidebar-button ${adminView === 'activity' ? 'active' : ''}`}
                    aria-label="View user activity"
                >
                    User Activity
                </button>
                <div style={{ marginTop: 'auto' }}>
                    <button
                        onClick={onLogout}
                        className="logout-button"
                        aria-label="Logout"
                    >
                        Logout
                    </button>
                </div>
            </nav>
            <main className="admin-main">
                <button
                    className="sidebar-toggle"
                    onClick={() => setIsSidebarOpen(true)}
                    aria-label="Open sidebar"
                >
                    ☰ Menu
                </button>
                {adminView === 'users' && <UserManagement />}
                {adminView === 'news' && <NewsManagement />}
                {adminView === 'activity' && <UserActivityLog />}
            </main>
        </div>
    );
}

// --- User Management with Enhanced Table Styling ---
function UserManagement() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
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
                    const userQuery = query(collection(db, PATHS.USERS), where("username", "==", username));
                    if ((await getDocs(userQuery)).empty) {
                        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
                        await setDoc(doc(db, PATHS.USERS, userCredential.user.uid), {
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

    if (loading) {
        return (
            <div>
                <div className="skeleton skeleton-header pulse"></div>
                <div className="skeleton skeleton-content pulse"></div>
            </div>
        );
    }

    return (
        <div>
            <h2 className="section-title">User Management</h2>
            <button
                onClick={handleCreateUsers}
                className="primary-button"
                style={{ marginBottom: '1.5rem' }}
                aria-label="Create all WP users"
            >
                Bulk Create Users
            </button>
            <div className="table-container">
                <table className="table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Cabang</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map((user) => (
                            <tr key={user.id}>
                                <td>{user.username}</td>
                                <td>{user.role}</td>
                                <td>{user.cabang}</td>
                                <td>
                                    <button
                                        onClick={() => handleAdminPasswordReset(user.username)}
                                        className="table-action-button"
                                        aria-label={`Reset password for ${user.username}`}
                                    >
                                        Reset Password
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- News Management ---
function NewsManagement() {
    const [newsItems, setNewsItems] = useState([]);
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [selectedNewsId, setSelectedNewsId] = useState(null);

    useEffect(() => {
        const newsQuery = query(
            collection(db, PATHS.NEWS),
            orderBy('createdAt', 'desc'),
            limit(20)
        );
        const unsubscribe = onSnapshot(newsQuery, (snapshot) => {
            const items = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setNewsItems(items);
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
            await addDoc(collection(db, PATHS.NEWS), {
                title, content, createdAt: serverTimestamp(), archived: false
            });
            setTitle('');
            setContent('');
            alert("News published successfully!");
        } catch (error) {
            console.error("Error publishing news:", error);
            alert("Failed to publish news.");
        }
    };

    return (
        <div>
            <h2 className="section-title">News & Statements</h2>
            <div className="news-grid">
                <div className="news-panel">
                    <h3 className="news-panel-title">Publish News</h3>
                    <form onSubmit={handlePublishNews} className="news-form">
                        <input
                            type="text"
                            value={title}
                            onChange={e => setTitle(e.target.value)}
                            placeholder="News Title"
                            className="form-input"
                            aria-label="News title"
                        />
                        <textarea
                            value={content}
                            onChange={e => setContent(e.target.value)}
                            placeholder="News content..."
                            rows="6"
                            className="form-input"
                            aria-label="News content"
                        ></textarea>
                        <button
                            type="submit"
                            className="primary-button"
                            aria-label="Publish news"
                        >
                            Publish News
                        </button>
                    </form>
                </div>
                <div className="news-panel">
                    <h3 className="news-panel-title">Assign Statements</h3>
                    <div className="news-list">
                        {newsItems.map(item => (
                            <div
                                key={item.id}
                                onClick={() => setSelectedNewsId(item.id)}
                                className={`news-item-selectable ${selectedNewsId === item.id ? 'active' : ''}`}
                            >
                                <p className="news-item-title">{item.title}</p>
                                <p className="news-item-date">{item.createdAt?.toDate().toLocaleDateString()}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
            {selectedNewsId && <StatementAssigner newsId={selectedNewsId} />}
        </div>
    );
}

// --- Statement Assigner ---
function StatementAssigner({ newsId }) {
    const [users, setUsers] = useState([]);
    const [statements, setStatements] = useState({});

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
        getDocs(usersQuery).then(snapshot => setUsers(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))));
        
        const statementsCollection = collection(db, `${PATHS.NEWS}/${newsId}/statements`);
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
                    await setDoc(doc(db, `${PATHS.NEWS}/${newsId}/statements`, userId), {
                        content: statements[userId], newsId, assignedAt: serverTimestamp()
                    });
                    successCount++;
                } catch (error) { console.error(`Failed to save for user ${userId}:`, error); }
            }
        }
        alert(`${successCount} statements saved successfully!`);
    };

    return (
        <div className="statement-assigner">
            <h3 className="news-panel-title">Assign Statements</h3>
            <div className="statement-list">
                {users.map(user => (
                    <div key={user.id} className="form-group">
                        <label className="form-label">{user.username} ({user.role})</label>
                        <textarea
                            value={statements[user.id] || ''}
                            onChange={e => handleStatementChange(user.id, e.target.value)}
                            placeholder={`Statement for ${user.username}...`}
                            rows="2"
                            className="form-input"
                            aria-label={`Statement for ${user.username}`}
                        />
                    </div>
                ))}
            </div>
            <button
                onClick={handleSaveStatements}
                className="primary-button"
                aria-label="Save all statements"
            >
                Save Statements
            </button>
        </div>
    );
}

// --- User Activity Log with Enhanced Table Styling ---
function UserActivityLog() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
        const unsubscribe = onSnapshot(usersQuery, (snapshot) => {
            const userList = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setUsers(userList.sort((a,b) => (b.lastLogin?.toMillis() || 0) - (a.lastLogin?.toMillis() || 0)));
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    if (loading) {
        return (
            <div>
                <div className="skeleton skeleton-header pulse"></div>
                <div className="skeleton skeleton-content pulse"></div>
            </div>
        );
    }

    if (selectedUser) {
        return <DetailedActivityView user={selectedUser} onBack={() => setSelectedUser(null)} />;
    }

    return (
        <div>
            <h2 className="section-title">User Activity Overview</h2>
            <div className="table-container">
                <table className="table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Last Login</th>
                            <th>IP Address (Demo)</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map((user) => (
                            <tr
                                key={user.id}
                                onClick={() => setSelectedUser(user)}
                            >
                                <td>{user.username}</td>
                                <td>{user.lastLogin ? user.lastLogin.toDate().toLocaleString() : 'Never'}</td>
                                <td>{user.ipAddress || 'N/A'}</td>
                                <td>
                                    <span className="table-link">View Log</span>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- Detailed Activity View ---
function DetailedActivityView({ user, onBack }) {
    const [log, setLog] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const logQuery = query(collection(db, `${PATHS.USERS}/${user.id}/activityLog`), orderBy('timestamp', 'desc'), limit(50));
        const unsubscribe = onSnapshot(logQuery, (snapshot) => {
            const logData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setLog(logData);
            setLoading(false);
        });
        return () => unsubscribe();
    }, [user.id]);

    if (loading) {
        return (
            <div>
                <div className="skeleton skeleton-header pulse"></div>
                <div className="skeleton skeleton-content pulse"></div>
            </div>
        );
    }

    return (
        <div>
            <button
                onClick={onBack}
                className="primary-button"
                style={{ marginBottom: '1.5rem' }}
                aria-label="Back to activity overview"
            >
                ← Back to Overview
            </button>
            <h2 className="section-title">Activity Log for {user.username}</h2>
            <p className="dashboard-subtitle" style={{ marginBottom: '1.5rem' }}>{user.role} - {user.cabang}</p>
            <div className="table-container">
                <table className="table">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Event Type</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log.map((entry) => (
                            <tr key={entry.id}>
                                <td>{entry.timestamp ? entry.timestamp.toDate().toLocaleString() : '...'}</td>
                                <td>
                                    <span className={`event-tag ${entry.type === 'LOGIN_SUCCESS' ? 'login' : entry.type === 'LOGOUT' ? 'logout' : 'copy'}`}>
                                        {entry.type}
                                    </span>
                                </td>
                                <td>{entry.newsId ? `News ID: ${entry.newsId.substring(0,10)}...` : entry.ipAddress || ''}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- Root Component ---
export default function Root() {
    return (
        <div className="app-root">
            <h1 className="app-header">PKR Campaign Platform</h1>
            <main className="app-main">
                <AppContainer />
            </main>
            <footer className="app-footer">
                ©2025 Parti Keadilan Rakyat
            </footer>
        </div>
    );
}
