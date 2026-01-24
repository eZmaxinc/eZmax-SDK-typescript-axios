# CommonResponseFilter

Definition of Filters for getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_AutoType** | **{ [key: string]: string; }** | List of filters that can be used in *sFilter* (Automatic types) | [optional] [default to undefined]
**a_AutoTypeHaving** | **{ [key: string]: string; }** | List of computed filters that can be used in *sFilter* (Automatic types) | [optional] [default to undefined]
**a_Enum** | **{ [key: string]: { [key: string]: string; }; }** | List of filters that can be used in *sFilter* (Enum types) | [optional] [default to undefined]

## Example

```typescript
import { CommonResponseFilter } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CommonResponseFilter = {
    a_AutoType,
    a_AutoTypeHaving,
    a_Enum,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
