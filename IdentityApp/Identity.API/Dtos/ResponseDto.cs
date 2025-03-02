namespace Identity.API.Dtos;

public class ResponseDto<T>
{
    public T? Data { get; set; }
    public bool IsSuccess { get; set; }
    public string? Message { get; set; }
}
