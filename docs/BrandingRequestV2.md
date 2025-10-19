# BrandingRequestV2

A Branding Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiBrandingID** | **number** | The unique ID of the Branding | [optional] [default to undefined]
**fkiDomainID** | **number** | The unique ID of the Domain | [optional] [default to undefined]
**objBrandingDescription** | [**MultilingualBrandingDescription**](MultilingualBrandingDescription.md) |  | [default to undefined]
**eBrandingLogo** | [**FieldEBrandingLogo**](FieldEBrandingLogo.md) |  | [default to undefined]
**eBrandingAlignlogo** | [**FieldEBrandingAlignlogo**](FieldEBrandingAlignlogo.md) |  | [optional] [default to undefined]
**sBrandingBase64** | **string** | The Base64 encoded binary content of the branding logo. This need to match image type selected in eBrandingLogo if you supply an image. If you select \&#39;Default\&#39;, the logo will be deleted and the default one will be used. | [optional] [default to undefined]
**iBrandingColor** | **number** | The primary color. This is a RGB color converted into integer | [default to undefined]
**sBrandingName** | **string** | The name of the Branding  This value will only be set if you wish to overwrite the default name. If you want to keep the default name, leave this property empty | [optional] [default to undefined]
**sEmailAddress** | **string** | The email address. | [optional] [default to undefined]
**bBrandingIsactive** | **boolean** | Whether the Branding is active or not | [default to undefined]

## Example

```typescript
import { BrandingRequestV2 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: BrandingRequestV2 = {
    pkiBrandingID,
    fkiDomainID,
    objBrandingDescription,
    eBrandingLogo,
    eBrandingAlignlogo,
    sBrandingBase64,
    iBrandingColor,
    sBrandingName,
    sEmailAddress,
    bBrandingIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
