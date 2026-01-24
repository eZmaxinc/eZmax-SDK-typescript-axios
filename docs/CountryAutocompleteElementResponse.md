# CountryAutocompleteElementResponse

A Country AutocompleteElement Response

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiCountryID** | **number** | The unique ID of the Country.  Here are some common values (Complete list must be retrieved from API):  |Value|Description| |-|-| |1|Canada| |2|United-States| | [default to undefined]
**sCountryNameX** | **string** | The name of the Country in the language of the requester | [default to undefined]
**sCountryShortname** | **string** | The shortname of the Country | [default to undefined]
**bCountryIsactive** | **boolean** | Whether the Country is active or not | [default to undefined]

## Example

```typescript
import { CountryAutocompleteElementResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CountryAutocompleteElementResponse = {
    pkiCountryID,
    sCountryNameX,
    sCountryShortname,
    bCountryIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
