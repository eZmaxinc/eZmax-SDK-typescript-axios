# ContacttitleAutocompleteElementResponse

A Contacttitle AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiContacttitleID** | **number** | The unique ID of the Contacttitle.  Valid values:  |Value|Description| |-|-| |1|Ms.| |2|Mr.| |4|(Blank)| |5|Me (For Notaries)| | [default to undefined]
**sContacttitleNameX** | **string** | The name of the Contacttitle in the language of the requester | [default to undefined]

## Example

```typescript
import { ContacttitleAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: ContacttitleAutocompleteElementResponse = {
    pkiContacttitleID,
    sContacttitleNameX,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
