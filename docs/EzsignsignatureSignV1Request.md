# EzsignsignatureSignV1Request

Request for POST /1/object/ezsignsignature/{pkiEzsignsignatureID}/sign

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsignsigningreasonID** | **number** | The unique ID of the Ezsignsigningreason | [optional] [default to undefined]
**fkiFontID** | **number** | The unique ID of the Font | [optional] [default to undefined]
**dEzsignsignatureCreditcardamount** | **string** | The amount of the Creditcard signature | [optional] [default to undefined]
**sValue** | **string** | The value required for the Ezsignsignature.  This can only be set if eEzsignsignatureType is **City**, **FieldText** or **FieldTextarea** | [optional] [default to undefined]
**eAttachmentsConfirmationDecision** | **string** | Whether the attachment are accepted or refused.  This can only be set if eEzsignsignatureType is **AttachmentsConfirmation** | [optional] [default to undefined]
**sAttachmentsRefusalReason** | **string** | The reason of refused.  This can only be set if eEzsignsignatureType is **AttachmentsConfirmation** | [optional] [default to undefined]
**sSvg** | **string** | The SVG of the signature.  This can only be set if eEzsignsignatureType is **Signature**_/_**Initials** and **bIsAutomatic** is false | [optional] [default to undefined]
**a_objFile** | [**Array&lt;CommonFile&gt;**](CommonFile.md) |  | [optional] [default to undefined]
**objCreditcard** | [**CustomCreditcardRequest**](CustomCreditcardRequest.md) |  | [optional] [default to undefined]
**bIsAutomatic** | **boolean** | Indicates if the Ezsignsignature was part of an automatic process or not.  This can only be true if eEzsignsignatureType is **Acknowledgement**, **City**, **Signature**, **Initials** or **Stamp**.  | [default to undefined]

## Example

```typescript
import { EzsignsignatureSignV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignatureSignV1Request = {
    fkiEzsignsigningreasonID,
    fkiFontID,
    dEzsignsignatureCreditcardamount,
    sValue,
    eAttachmentsConfirmationDecision,
    sAttachmentsRefusalReason,
    sSvg,
    a_objFile,
    objCreditcard,
    bIsAutomatic,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
