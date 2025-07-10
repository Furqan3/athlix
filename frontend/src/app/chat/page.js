'use client';
import React, { useState, useEffect, useRef } from 'react';
import { 
  MessageCircle, 
  Send, 
  Plus, 
  User, 
  LogOut, 
  Trash2, 
  Camera, 
  Menu, 
  X, 
  AlertCircle, 
  Download,
  Loader2,
  Bot,
  Image as ImageIcon
} from 'lucide-react';
import { jsPDF } from 'jspdf';

// API Configuration
const API_BASE_URL = "https://app.athlix.fit";

// Utility Functions
const apiRequest = async (endpoint, options = {}) => {
  const token = localStorage.getItem("access_token");
  const headers = {
    ...(token && { Authorization: `Bearer ${token}` }),
    ...options.headers,
  };

  // Don't set Content-Type for FormData - let browser set it
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }

  console.log(`Making API request to: ${API_BASE_URL}${endpoint}`);

  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers,
    });

    if (!response.ok) {
      let errorData;
      try {
        errorData = await response.json();
      } catch (parseError) {
        errorData = { detail: `HTTP ${response.status}: ${response.statusText}` };
      }

      // Handle FastAPI validation errors (422)
      if (errorData.detail && Array.isArray(errorData.detail)) {
        // Map validation errors to a readable string
        const validationMsg = errorData.detail
          .map((err) => `${err.loc?.join('.') || ''}: ${err.msg}`)
          .join('; ');
        throw new Error(validationMsg || "Validation error");
      }

      const errorMessage = errorData.detail || errorData.message || `Request failed with status ${response.status}`;
      throw new Error(errorMessage);
    }

    return response.json();
  } catch (error) {
    console.error('API request error:', error);

    if (error.name === "TypeError" && error.message.includes("fetch")) {
              throw new Error("Unable to connect to server. Please check if the backend is running.");
    }

    // Always return a string error message
    if (error instanceof Error) {
      throw error;
    } else {
      throw new Error(String(error));
    }
  }
};

// Components
const LoadingSpinner = ({ size = "small" }) => (
  <div className={`flex justify-center items-center ${size === "large" ? "h-64" : "h-12"}`}>
    <Loader2 className={`animate-spin text-indigo-600 ${size === "large" ? "w-12 h-12" : "w-6 h-6"}`} />
  </div>
);

const Alert = ({ type, message, onClose }) => {
  const bgColor = type === "error" ? "bg-red-50 border-red-200" : "bg-green-50 border-green-200";
  const textColor = type === "error" ? "text-red-800" : "text-green-800";

  return (
    <div className={`border rounded-xl p-4 mb-4 ${bgColor}`}>
      <div className="flex items-center">
        <AlertCircle className={`w-5 h-5 mr-2 ${textColor}`} />
        <span className={textColor}>{message}</span>
        {onClose && (
          <button onClick={onClose} className="ml-auto">
            <X className="w-4 h-4" />
          </button>
        )}
      </div>
    </div>
  );
};

const Button = ({ children, variant = "primary", className = "", ...props }) => {
  const baseClasses = "px-4 py-2 rounded-xl font-semibold transition-all duration-200 disabled:opacity-50 disabled:cursor-not-allowed";
  const variants = {
    primary: "bg-indigo-600 hover:bg-indigo-700 text-white",
    secondary: "bg-gray-100 hover:bg-gray-200 text-gray-800",
    danger: "bg-red-600 hover:bg-red-700 text-white",
    ghost: "hover:bg-gray-100 text-gray-600",
  };

  return (
    <button className={`${baseClasses} ${variants[variant]} ${className}`} {...props}>
      {children}
    </button>
  );
};

// Simple markdown renderer
const renderMarkdown = (text) => {
  if (!text) return text;

  // Convert **bold** to <strong>
  text = text.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  
  // Convert *italic* to <em>
  text = text.replace(/(?<!\*)\*(?!\*)([^*]+)\*(?!\*)/g, '<em>$1</em>');
  
  // Convert # Header to <h3>
  text = text.replace(/^# (.*$)/gm, '<h3 class="text-lg font-bold mb-2">$1</h3>');
  
  // Convert ## Header to <h4>
  text = text.replace(/^## (.*$)/gm, '<h4 class="text-base font-bold mb-2">$1</h4>');
  
  // Convert ### Header to <h5>
  text = text.replace(/^### (.*$)/gm, '<h5 class="text-sm font-bold mb-1">$1</h5>');
  
  // Convert line breaks to <br>
  text = text.replace(/\n/g, '<br>');
  
  // Convert bullet points - (dash) to •
  text = text.replace(/^- (.*$)/gm, '• $1');
  
  // Convert numbered lists
  text = text.replace(/^\d+\. (.*$)/gm, '<div class="ml-4">• $1</div>');
  
  // Convert `code` to <code>
  text = text.replace(/`([^`]+)`/g, '<code class="bg-gray-100 px-1 py-0.5 rounded text-sm font-mono">$1</code>');
  
  // Convert [link](url) to <a>
  text = text.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" class="text-blue-600 hover:text-blue-800 underline" target="_blank" rel="noopener noreferrer">$1</a>');

  return text;
};

const ChatMessage = ({ message, isUser, timestamp, imageUrl }) => {
  const renderedMessage = isUser ? message : renderMarkdown(message);
  
  return (
    <div className={`flex mb-6 ${isUser ? "justify-end" : "justify-start"}`}>
      <div className="flex items-start space-x-3 max-w-4xl">
        {/* Avatar */}
        {!isUser && (
          <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
            <Bot className="w-4 h-4 text-white" />
          </div>
        )}
        
        {/* Message Content */}
        <div
          className={`px-4 py-3 rounded-2xl shadow-sm ${
            isUser 
              ? "bg-gradient-to-r from-indigo-600 to-purple-600 text-white rounded-br-md" 
              : "bg-white border border-gray-200 text-gray-800 rounded-bl-md"
          }`}
        >
          {/* Image if present */}
          {imageUrl && (
            <div className="mb-3">
              <img 
                src={imageUrl} 
                alt="Image" 
                className="max-w-sm rounded-lg shadow-md border border-gray-200"
                style={{ maxHeight: '300px', objectFit: 'contain' }}
              />
            </div>
          )}
          
          {/* Message text */}
          {isUser ? (
            <p className="whitespace-pre-wrap leading-relaxed">{message}</p>
          ) : (
            <div 
              className="prose prose-sm max-w-none leading-relaxed"
              dangerouslySetInnerHTML={{ __html: renderedMessage }}
            />
          )}
          
          {/* Timestamp */}
          {timestamp && (
            <p className={`text-xs mt-2 opacity-75 ${isUser ? "text-indigo-100" : "text-gray-500"}`}>
              {new Date(timestamp).toLocaleTimeString()}
            </p>
          )}
        </div>

        {/* User Avatar */}
        {isUser && (
          <div className="w-8 h-8 bg-gradient-to-br from-gray-400 to-gray-600 rounded-full flex items-center justify-center flex-shrink-0 mt-1">
            <User className="w-4 h-4 text-white" />
          </div>
        )}
      </div>
    </div>
  );
};

const ImageUpload = ({ onImageUpload, loading }) => {
  const [dragOver, setDragOver] = useState(false);
  const [preview, setPreview] = useState(null);
  const fileInputRef = useRef(null);

  const handleDrop = (e) => {
    e.preventDefault();
    setDragOver(false);
    const files = e.dataTransfer.files;
    if (files[0]) {
      createPreview(files[0]);
      onImageUpload(files[0]);
    }
  };

  const handleFileSelect = (e) => {
    const file = e.target.files[0];
    if (file) {
      createPreview(file);
      onImageUpload(file);
    }
  };

  const createPreview = (file) => {
    const reader = new FileReader();
    reader.onload = (e) => setPreview(e.target.result);
    reader.readAsDataURL(file);
  };

  return (
    <div className="space-y-4">
      <div
        onDrop={handleDrop}
        onDragOver={(e) => e.preventDefault()}
        onDragEnter={() => setDragOver(true)}
        onDragLeave={() => setDragOver(false)}
        className={`border-2 border-dashed rounded-xl p-8 text-center transition-all duration-200 ${
          dragOver 
            ? "border-indigo-500 bg-indigo-50 scale-105" 
            : "border-gray-300 hover:border-gray-400"
        }`}
      >
        <input ref={fileInputRef} type="file" accept="image/*" onChange={handleFileSelect} className="hidden" />

        <div className="w-16 h-16 text-gray-400 mx-auto mb-4 flex items-center justify-center">
          <Camera className="w-16 h-16" />
        </div>

        <div className="space-y-2">
          <p className="text-lg font-medium text-gray-700">
            Drop your  image here
          </p>
          <p className="text-gray-500">
            or{" "}
            <button
              onClick={() => fileInputRef.current?.click()}
              className="text-indigo-600 hover:text-indigo-700 font-medium underline"
              disabled={loading}
            >
              browse files
            </button>
          </p>
          <p className="text-sm text-gray-400">
            Supports JPG, PNG, GIF • Max 10MB
          </p>
        </div>

        {loading && (
          <div className="mt-6">
            <Loader2 className="w-8 h-8 animate-spin mx-auto text-indigo-600" />
            <p className="text-sm text-gray-600 mt-3 font-medium">
              Analyzing your image...
            </p>
          </div>
        )}
      </div>

      {/* Image Preview */}
      {preview && !loading && (
        <div className="bg-gray-50 rounded-xl p-4">
          <p className="text-sm font-medium text-gray-700 mb-3">Preview:</p>
          <img 
            src={preview} 
            alt="Upload preview" 
            className="max-w-full h-48 object-contain mx-auto rounded-lg shadow-sm border border-gray-200"
          />
        </div>
      )}
    </div>
  );
};

// Main Chat Component
const ChatPage = () => {
  const [sessions, setSessions] = useState([]);
  const [selectedSession, setSelectedSession] = useState(null);
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [sessionLoading, setSessionLoading] = useState(false);
  const [error, setError] = useState("");
  const [userInfo, setUserInfo] = useState(null);
  const [showImageUpload, setShowImageUpload] = useState(false);
  const [imageUploadLoading, setImageUploadLoading] = useState(false);
  const [showSidebar, setShowSidebar] = useState(false);
  const [deletingSessionId, setDeletingSessionId] = useState(null);
  const [deletingAllSessions, setDeletingAllSessions] = useState(false);
  const messagesEndRef = useRef(null);

  useEffect(() => {
    const token = localStorage.getItem("access_token");
    const user = localStorage.getItem("user");

    if (!token) {
      window.location.href = "/signin";
      return;
    }

    if (user) {
      try {
        setUserInfo(JSON.parse(user));
      } catch (error) {
        console.error("Error parsing user data:", error);
      }
    }
    fetchSessions();
  }, []);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const fetchSessions = async () => {
    setSessionLoading(true);
    setError("");
    try {
      const response = await apiRequest("/chat/sessions");
      setSessions(response.sessions || []);
    } catch (err) {
      console.error("Error fetching sessions:", err);
      if (err.message.includes("Unable to connect to server")) {
        setError(
          "Cannot connect to the backend server. Please ensure the FastAPI server is running."
        );
      } else {
        setError("Failed to fetch chat sessions: " + err.message);
      }
    } finally {
      setSessionLoading(false);
    }
  };

  const selectSession = async (sessionId) => {
    setSelectedSession(sessionId);
    setLoading(true);
    setError("");
    try {
      const response = await apiRequest(`/chat/session/${sessionId}`);
      const formattedMessages = response.messages.map((msg) => ({
        content: msg.content,
        isUser: msg.is_user,
        timestamp: msg.timestamp,
        imageUrl: msg.has_image && msg.image_url ? API_BASE_URL + msg.image_url : null
      }));
      setMessages(formattedMessages);
    } catch (err) {
      console.error("Error fetching messages:", err);
      setError("Failed to fetch messages");
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = async () => {
    if (!newMessage.trim() || loading) return;

    const userMessage = {
      content: newMessage,
      isUser: true,
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage]);
    setLoading(true);
    setError("");

    const messageToSend = newMessage;
    setNewMessage("");

    try {
      const formData = new FormData();
      formData.append("message", messageToSend);
      if (selectedSession) {
        formData.append("session_id", selectedSession);
      }

      const response = await apiRequest("/chat/message", {
        method: "POST",
        body: formData,
      });

      const aiMessage = {
        content: response.response,
        isUser: false,
        timestamp: response.timestamp,
      };

      setMessages((prev) => [...prev, aiMessage]);
      setSelectedSession(response.session_id);

      // Refresh sessions list if this was a new session
      if (!selectedSession) {
        fetchSessions();
      }
    } catch (err) {
      console.error("Error sending message:", err);
      const errorMessage = {
        content: `Sorry, I encountered an error: ${err.message}`,
        isUser: false,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
      setError("Failed to send message");
    } finally {
      setLoading(false);
    }
  };

  const createNewSession = async () => {
    try {
      const response = await apiRequest("/chat/new", {
        method: "POST",
        body: JSON.stringify({}),
      });
      
      setSelectedSession(response.session_id);
      setMessages([]);
      setError("");
      
      // Refresh sessions list
      fetchSessions();
    } catch (err) {
      console.error("Error creating new session:", err);
      // Fallback to client-side new session
      setSelectedSession(null);
      setMessages([]);
      setError("");
    }
  };

  const deleteSession = async (sessionId, event) => {
    event.stopPropagation();
    setDeletingSessionId(sessionId);
    try {
      await apiRequest(`/chat/session/${sessionId}`, { method: "DELETE" });
      setSessions((prev) => prev.filter((session) => session.session_id !== sessionId));

      if (selectedSession === sessionId) {
        setSelectedSession(null);
        setMessages([]);
        setError("");
      }
    } catch (err) {
      setError("Failed to delete session");
    } finally {
      setDeletingSessionId(null);
    }
  };

  const deleteAllSessions = async () => {
    setDeletingAllSessions(true);
    try {
      await apiRequest("/chat/sessions/all", { method: "DELETE" });
      setSessions([]);
      setSelectedSession(null);
      setMessages([]);
      setError("");
    } catch (err) {
      setError("Failed to delete all sessions");
    } finally {
      setDeletingAllSessions(false);
    }
  };

  const handleImageUpload = async (file) => {
    // Validate file size (10MB limit)
    if (file.size > 10 * 1024 * 1024) {
      setError("File size must be less than 10MB");
      return;
    }

    // Validate file type
    if (!file.type.startsWith('image/')) {
      setError("Please select a valid image file");
      return;
    }

    setImageUploadLoading(true);
    setError("");

    try {
      // Create a user message first
      const userMessage = {
        content: "I've uploaded an image for analysis.",
        isUser: true,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, userMessage]);

      const formData = new FormData();
      formData.append("file", file);
      formData.append("message", "Please analyze this image and provide insights.");
      
      if (selectedSession) {
        formData.append("session_id", selectedSession);
      }

      const response = await apiRequest("/chat/message", {
        method: "POST",
        body: formData,
      });

      setShowImageUpload(false);

      const aiMessage = {
        content: response.response,
        isUser: false,
        timestamp: response.timestamp,
      };

      setMessages((prev) => [...prev, aiMessage]);
      setSelectedSession(response.session_id);

      // Refresh sessions list if this was a new session
      if (!selectedSession) {
        fetchSessions();
      }
    } catch (err) {
      const errorMessage = {
        content: `Failed to upload image: ${err.message}`,
        isUser: false,
        timestamp: new Date().toISOString(),
      };
      setMessages((prev) => [...prev, errorMessage]);
      setError("Failed to upload image: " + err.message);
    } finally {
      setImageUploadLoading(false);
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("access_token");
    localStorage.removeItem("user");
    window.location.href = "/signin";
  };

  const formatSessionTitle = (session) => {
    if (session.last_message) {
      return session.last_message.length > 30 ? session.last_message.substring(0, 30) + "..." : session.last_message;
    }
    return `Chat ${new Date(session.created_at).toLocaleDateString()}`;
  };

  const downloadChatAsPDF = async () => {
    if (!selectedSession || messages.length === 0) {
      setError("No messages to download. Please select a conversation.");
      return;
    }

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 20;
    const maxWidth = pageWidth - 2 * margin;
    let y = margin;

    doc.setFontSize(16);
    doc.setFont("helvetica", "bold");
    doc.text(`AI Chat - ${new Date().toLocaleDateString()}`, margin, y);
    y += 10;

    for (const msg of messages) {
      const sender = msg.isUser ? "User" : "AI Assistant";
      const timestamp = new Date(msg.timestamp).toLocaleString();

      doc.setFontSize(12);
      doc.setFont("helvetica", "bold");
      doc.text(`${sender} (${timestamp})`, margin, y);
      y += 7;

      // Only show a placeholder for images, don't fetch them
      if (msg.imageUrl) {
        doc.setFont("helvetica", "italic");
        doc.setFontSize(10);
        doc.text('[Image not included in PDF]', margin, y);
        y += 6;
      }

      let content = msg.content;
      // Basic Markdown-like formatting
      content = content.replace(/\*\*(.*?)\*\*/g, "$1"); // Remove bold markers
      content = content.replace(/(?<!\*)\*(?!\*)(.*?)(?<!\*)\*(?!\*)/g, "$1"); // Remove italic markers
      content = content.replace(/`([^`]+)`/g, "$1"); // Remove code markers
      content = content.replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)"); // Convert links

      // Split content into lines for wrapping
      const lines = doc.splitTextToSize(content, maxWidth);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      lines.forEach((line) => {
        if (y > pageHeight - margin) {
          doc.addPage();
          y = margin;
        }
        doc.text(line, margin, y);
        y += 5;
      });

      y += 5; // Space between messages
    }

    // Save the PDF
    doc.save(`AI_Chat_${selectedSession || "new"}.pdf`);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-white/80 backdrop-blur-lg border-b border-white/20 shadow-sm">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-4">
              <button
                onClick={() => setShowSidebar(!showSidebar)}
                className="lg:hidden p-2 color:black rounded-xl hover:bg-gray-100/50 transition-colors"
              >
                <Menu className="w-5 h-5" />
              </button>
              <div className="flex items-center space-x-3">
                
                <div>
                  <img src="/logo.png" alt="AI Logo" className="h-9 " />
                  <p className="text-sm text-gray-600">
                    Welcome, {userInfo?.first_name ? `${userInfo.first_name}` : "User"}
                  </p>
                </div>
              </div>
            </div>
            <Button onClick={handleLogout} variant="danger" className="flex items-center shadow-sm">
  <LogOut className="w-4 h-4" />
  <span className="ml-2 text-sm">Logout</span>
</Button>

          </div>
        </div>
      </div>

      {/* Connection Status Indicator */}
      {error && error.includes("Cannot connect") && (
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="bg-red-50 border border-red-200 rounded-xl p-4 shadow-sm">
            <div className="flex items-center">
              <AlertCircle className="w-5 h-5 text-red-600 mr-3" />
              <div>
                <h3 className="text-red-800 font-medium">Backend Connection Error</h3>
                <p className="text-red-700 text-sm mt-1">Make sure your FastAPI backend is running:</p>
                <code className="block bg-red-100 text-red-800 p-2 rounded mt-2 text-xs font-mono">
                  uvicorn main:app --reload --host 0.0.0.0 --port 8000
                </code>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="max-w-7xl mx-auto px-4 py-6">
        <div className="flex gap-6 h-[calc(100vh-140px)]">
          {/* Sidebar */}
          <div
            className={`${showSidebar ? "translate-x-0" : "-translate-x-full"} lg:translate-x-0 fixed lg:static inset-y-0 left-0 z-50 w-80 lg:w-80 bg-white/70 backdrop-blur-xl border border-white/20 rounded-2xl shadow-xl p-6 flex flex-col transform transition-all duration-300 ease-in-out`}
          >
            <div className="flex items-center justify-between mb-6">
              <h2 className="text-lg font-bold text-gray-900">Conversations</h2>
              <button onClick={() => setShowSidebar(false)} className="lg:hidden p-1 rounded-lg hover:bg-gray-100/50">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="space-y-3 mb-6">
              <Button onClick={createNewSession} className="w-full flex items-center justify-center shadow-sm" variant="primary">
                <Plus className="w-4 h-4" />
                <span className="ml-2">New Chat</span>
              </Button>

              <Button onClick={() => setShowImageUpload(true)} className="w-full flex items-center justify-center shadow-sm" variant="secondary">
                <Camera className="w-4 h-4" />
                <span className="ml-2">Analyze Image</span>
              </Button>

              <Button onClick={downloadChatAsPDF} className="w-full flex items-center justify-center shadow-sm" variant="secondary" disabled={!selectedSession || messages.length === 0}>
                <Download className="w-4 h-4" />
                <span className="ml-2">Download Chat</span>
              </Button>
              <Button onClick={deleteAllSessions} className="w-full flex items-center justify-center shadow-sm" variant="danger" disabled={deletingAllSessions || sessions.length === 0}>
                {deletingAllSessions ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                <span className="ml-2">{deletingAllSessions ? "Deleting..." : "Delete All"}</span>
              </Button>

                          </div>

            {sessionLoading ? (
              <LoadingSpinner />
            ) : (
              <div className="flex-1 overflow-y-auto">
                {sessions.length === 0 ? (
                  <div className="text-center text-gray-500 py-12">
                    <div className="w-16 h-16 text-gray-300 mx-auto mb-4 flex items-center justify-center">
                      <MessageCircle className="w-16 h-16" />
                    </div>
                    <p className="font-medium">No conversations yet</p>
                    <p className="text-sm mt-1">Start your first chat!</p>
                  </div>
                ) : (
                  <ul className="space-y-2">
                    {sessions.map((session) => (
                      <li
                        key={session.session_id}
                        onClick={() => selectSession(session.session_id)}
                        className={`p-4 rounded-xl cursor-pointer transition-all duration-200 relative group ${selectedSession === session.session_id
                            ? "bg-gradient-to-r from-indigo-100 to-purple-100 text-indigo-900 border border-indigo-200 shadow-sm"
                            : "bg-white/50 text-gray-700 hover:bg-white/80 hover:shadow-sm"}`}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center space-x-2">
                              <p className="font-medium truncate flex-1">{formatSessionTitle(session)}</p>
                              {session.has_images && (
                                <div className="flex-shrink-0">
                                  <ImageIcon className="w-4 h-4 text-indigo-500" />
                                </div>
                              )}
                            </div>
                            <p className="text-xs opacity-70 mt-1">
                              {new Date(session.last_activity).toLocaleDateString()} • {session.message_count} messages
                            </p>
                          </div>
                          <button
                            onClick={(e) => deleteSession(session.session_id, e)}
                            disabled={deletingSessionId === session.session_id}
                            className="p-2 text-gray-400 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-all duration-200 rounded-lg hover:bg-red-50"
                          >
                            {deletingSessionId === session.session_id ? <Loader2 className="w-4 h-4 animate-spin" /> : <Trash2 className="w-4 h-4" />}
                          </button>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>

          {/* Chat Area */}
          <div className="flex-1 bg-white/70 backdrop-blur-xl border border-white/20 rounded-2xl shadow-xl flex flex-col overflow-hidden">
            {selectedSession || messages.length > 0 ? (
              <>
                {/* Messages */}
                <div className="flex-1 overflow-y-auto p-6 space-y-1">
                  {messages.length > 0 ? (
                    messages.map((msg, index) => (
                      <ChatMessage
                        key={index}
                        message={msg.content}
                        isUser={msg.isUser}
                        timestamp={msg.timestamp}
                        imageUrl={msg.imageUrl}
                      />
                    ))
                  ) : (
                    <div className="flex items-center justify-center h-full">
                      <div className="text-center text-gray-500 max-w-md">
                        <div className="w-20 h-20 text-gray-300 mx-auto mb-4 flex items-center justify-center">
                          <MessageCircle className="w-20 h-20" />
                        </div>
                        <p className="text-sm">No messages in this conversation yet</p>
                        <p className="text-xs mt-1">Start typing to begin!</p>
                      </div>
                    </div>
                  )}

                  {loading && (
                    <div className="flex justify-start mb-6">
                      <div className="flex items-start space-x-3">
                        <div className="w-8 h-8 bg-gradient-to-br from-indigo-500 to-purple-600 rounded-full flex items-center justify-center flex-shrink-0">
                          <Bot className="w-4 h-4 text-white" />
                        </div>
                        <div className="bg-white border border-gray-200 rounded-2xl rounded-bl-md px-4 py-3 shadow-sm">
                          <div className="flex items-center space-x-2">
                            <Loader2 className="w-4 h-4 animate-spin" />
                            <span className="text-gray-600 text-sm">AI is thinking...</span>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}

                  <div ref={messagesEndRef} />
                </div>

                {/* Input Area */}
                <div className="border-t border-gray-200/50 p-6">
                  <div className="flex items-end space-x-3">
                    <div className="flex-1 bg-white rounded-2xl text-black border border-gray-200 shadow-sm focus-within:ring-2 focus-within:ring-indigo-500 focus-within:border-transparent">
                      <textarea
                        value={newMessage}
                        onChange={(e) => setNewMessage(e.target.value)}
                        placeholder="Type your message here..."
                        className="w-full p-4 border-0 rounded-2xl resize-none focus:outline-none min-h-[50px] max-h-32"
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !e.shiftKey) {
                            e.preventDefault();
                            sendMessage();
                          }
                        }}
                        disabled={loading}
                        rows={1}
                      />
                    </div>
                    <Button
                      onClick={sendMessage}
                      disabled={loading || !newMessage.trim()}
                      variant="primary"
                      className="flex items-center shadow-lg h-[50px] px-6"
                    >
                      {loading ? <Loader2 className="w-5 h-5 animate-spin" /> : <Send className="w-5 h-5" />}
                    </Button>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex-1 flex items-center justify-center p-12">
                <div className="text-center max-w-md">
                  <img src="/logo.png" alt="AI Logo" className="h-16 mb-4 mx-auto" />
                  <h3 className="text-xl font-bold text-gray-900 mb-2">Welcome to Athlix</h3>
                  <p className="text-gray-600 mb-8 leading-relaxed">
                    Get personalized health insights and recommendations. Start a conversation or upload an image for analysis.
                  </p>
                  <div className="space-y-3">
                    <Button onClick={createNewSession} className="w-full flex items-center justify-center shadow-lg">
                      <Plus className="w-5 h-5" />
                      <span className="ml-2">Start New Conversation</span>
                    </Button>
                    <Button onClick={() => setShowImageUpload(true)} className="w-full flex items-center justify-center shadow-lg" variant="secondary">
                      <Camera className="w-5 h-5" />
                      <span className="ml-2">Analyze Image</span>
                    </Button>
                  </div>
                </div>
              </div>
            )}

            {error && <Alert type="error" message={error} onClose={() => setError("")} />}
          </div>
        </div>
      </div>

      {/* Image Upload Modal */}
      {showImageUpload && (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
          <div className="bg-white rounded-2xl shadow-2xl max-w-lg w-full max-h-[90vh] overflow-y-auto">
            <div className="p-6">
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-xl font-bold text-gray-900">Upload Image</h3>
                  <p className="text-gray-600 text-sm mt-1">Get AI-powered analysis and recommendations</p>
                </div>
                <button
                  onClick={() => setShowImageUpload(false)}
                  className="p-2 text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-100 transition-colors"
                  disabled={imageUploadLoading}
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <ImageUpload onImageUpload={handleImageUpload} loading={imageUploadLoading} />
            </div>
          </div>
        </div>
      )}

      {/* Mobile Sidebar Overlay */}
      {showSidebar && (
        <div 
          className="fixed inset-0 bg-black/25 backdrop-blur-sm z-40 lg:hidden"
          onClick={() => setShowSidebar(false)}
        />
      )}
    </div>
  );
};

export default ChatPage;
