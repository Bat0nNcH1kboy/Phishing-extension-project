// Service worker is reserved for future background checks and notifications.
chrome.runtime.onInstalled.addListener(() => {
  console.log('Anti-phishing extension installed');
});
