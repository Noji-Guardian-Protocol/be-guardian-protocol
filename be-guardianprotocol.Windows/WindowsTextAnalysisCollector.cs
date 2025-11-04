using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using be_guardianprotocol.Core.Interfaces;
using be_guardianprotocol.Core.Models;
using be_guardianprotocol.Core.Enums;
using be_guardianprotocol.Core.Services;

namespace be_guardianprotocol.Windows
{
    public class WindowsTextAnalysisCollector : ISignalCollector
    {
        private readonly NetworkConnectionLogger _logger;
        private static readonly List<string> _typedText = new();
        private static readonly List<string> _words = new();
        private static readonly Dictionary<int, int> _wordLengthCounts = new();
        private static int _totalWords = 0;
        private static readonly List<char> _currentWord = new();

        public WindowsTextAnalysisCollector()
        {
            _logger = new NetworkConnectionLogger();
        }

        public async Task<IEnumerable<SignalCapture>> CollectAsync()
        {
            var results = new List<SignalCapture>();

            try
            {
                // This would integrate with keyboard collector to analyze typed text
                var recentText = GetRecentTypedText();
                AnalyzeText(recentText);

                var capture = new SignalCapture
                {
                    Type = SignalTypes.TextAnalysis,
                    IsConnected = true,
                    Timestamp = DateTime.Now,
                    
                    // Word statistics
                    WordCount = _totalWords,
                    AverageWordLength = CalculateAverageWordLength(),
                    WordLengthStdDev = CalculateWordLengthStdDev(),
                    
                    // Word length distribution
                    WordLength1Count = _wordLengthCounts.GetValueOrDefault(1, 0),
                    WordLength2Count = _wordLengthCounts.GetValueOrDefault(2, 0),
                    WordLength3Count = _wordLengthCounts.GetValueOrDefault(3, 0),
                    WordLength4Count = _wordLengthCounts.GetValueOrDefault(4, 0),
                    WordLength5Count = _wordLengthCounts.GetValueOrDefault(5, 0),
                    WordLength6Count = _wordLengthCounts.GetValueOrDefault(6, 0),
                    WordLength7Count = _wordLengthCounts.GetValueOrDefault(7, 0),
                    WordLength8Count = _wordLengthCounts.GetValueOrDefault(8, 0),
                    WordLength9Count = _wordLengthCounts.GetValueOrDefault(9, 0),
                    WordLength10Count = _wordLengthCounts.GetValueOrDefault(10, 0),
                    WordLength11PlusCount = _wordLengthCounts.Where(kvp => kvp.Key >= 11).Sum(kvp => kvp.Value),
                    
                    // Text patterns
                    TypingPattern = AnalyzeTypingPattern(),
                    LanguagePattern = DetectLanguagePattern(),
                    TextComplexity = CalculateTextComplexity()
                };

                await _logger.LogConnectionAsync(capture);
                results.Add(capture);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Text analysis error: {ex.Message}");
            }

            return results;
        }

        private string GetRecentTypedText()
        {
            // This would integrate with keyboard collector to get actual typed text
            // For now, return empty string as placeholder
            return "";
        }

        private void AnalyzeText(string text)
        {
            if (string.IsNullOrEmpty(text)) return;

            var words = Regex.Split(text, @"\s+")
                .Where(w => !string.IsNullOrEmpty(w) && Regex.IsMatch(w, @"^[a-zA-Z]+$"))
                .ToList();

            foreach (var word in words)
            {
                _words.Add(word);
                _totalWords++;
                
                var length = Math.Min(word.Length, 11);
                _wordLengthCounts[length] = _wordLengthCounts.GetValueOrDefault(length, 0) + 1;
            }

            // Keep only recent words (last 100)
            if (_words.Count > 100)
            {
                _words.RemoveRange(0, _words.Count - 100);
            }
        }

        private double CalculateAverageWordLength()
        {
            if (_words.Count == 0) return 0;
            return _words.Average(w => w.Length);
        }

        private double CalculateWordLengthStdDev()
        {
            if (_words.Count == 0) return 0;
            
            var avg = CalculateAverageWordLength();
            var variance = _words.Average(w => Math.Pow(w.Length - avg, 2));
            return Math.Sqrt(variance);
        }

        private string AnalyzeTypingPattern()
        {
            if (_words.Count < 5) return "Insufficient";
            
            var avgLength = CalculateAverageWordLength();
            if (avgLength > 6) return "Complex";
            if (avgLength > 4) return "Moderate";
            return "Simple";
        }

        private string DetectLanguagePattern()
        {
            if (_words.Count < 10) return "Unknown";
            
            // Simple language detection based on common patterns
            var commonEnglishWords = new[] { "the", "and", "or", "but", "in", "on", "at", "to", "for", "of", "with", "by" };
            var englishWordCount = _words.Count(w => commonEnglishWords.Contains(w.ToLower()));
            
            if (englishWordCount > _words.Count * 0.1) return "English";
            return "Other";
        }

        private double CalculateTextComplexity()
        {
            if (_words.Count == 0) return 0;
            
            var uniqueWords = _words.Distinct().Count();
            var avgWordLength = CalculateAverageWordLength();
            
            // Simple complexity score based on vocabulary diversity and word length
            return (uniqueWords / (double)_words.Count) * avgWordLength;
        }

        public static void AddTypedCharacter(char character)
        {
            if (char.IsLetter(character))
            {
                _currentWord.Add(character);
            }
            else if (char.IsWhiteSpace(character) && _currentWord.Count > 0)
            {
                var word = new string(_currentWord.ToArray());
                _words.Add(word);
                _totalWords++;
                
                var length = Math.Min(word.Length, 11);
                _wordLengthCounts[length] = _wordLengthCounts.GetValueOrDefault(length, 0) + 1;
                
                _currentWord.Clear();
            }
        }
    }
}