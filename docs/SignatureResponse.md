# SignatureResponse

A Signature Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiSignatureID** | **number** | The unique ID of the Signature | [default to undefined]
**fkiFontID** | **number** | The unique ID of the Font | [optional] [default to undefined]
**sSignatureUrl** | **string** | The URL of the SVG file for the Signature | [optional] [default to undefined]
**sSignatureUrlinitials** | **string** | The URL of the SVG file for the Initials | [optional] [default to undefined]

## Example

```typescript
import { SignatureResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: SignatureResponse = {
    pkiSignatureID,
    fkiFontID,
    sSignatureUrl,
    sSignatureUrlinitials,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
