# LanguageAutocompleteElementResponse

A Language AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**bLanguageIsactive** | **boolean** | Whether the Language is active or not | [default to undefined]

## Example

```typescript
import { LanguageAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: LanguageAutocompleteElementResponse = {
    pkiLanguageID,
    sLanguageNameX,
    bLanguageIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
