namespace KinoshitaProductions.AuthClient.Enums;

[Flags]
public enum AuthOperationResult
{
    ErrorCannotDetermine = 1,
    Unauthorized = 2,
    Success = 4,
    ResultNotPersisted = 8,
    NoOp = Success | 16,
}