# ObjectSupplierApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**supplierGetListV1**](#suppliergetlistv1) | **GET** /1/object/supplier/getList | Retrieve Supplier list|
|[**supplierImportIntoEDMV1**](#supplierimportintoedmv1) | **POST** /1/object/supplier/{pkiSupplierID}/importIntoEDM | Import attachments into the Supplier|

# **supplierGetListV1**
> SupplierGetListV1Response supplierGetListV1()



### Example

```typescript
import {
    ObjectSupplierApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplierApi(configuration);

let eOrderBy: 'pkiSupplierID_ASC' | 'pkiSupplierID_DESC' | 'fkiPaymentmethodID_ASC' | 'fkiPaymentmethodID_DESC' | 'sSupplierName_ASC' | 'sSupplierName_DESC' | 'sSupplierCode_ASC' | 'sSupplierCode_DESC' | 'sSupplierAccount_ASC' | 'sSupplierAccount_DESC' | 'bSupplierIsactive_ASC' | 'bSupplierIsactive_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC' | 'sPaymentmethodDescriptionX_ASC' | 'sPaymentmethodDescriptionX_DESC' | 'sElectronicfundstransferbankaccountTransit_ASC' | 'sElectronicfundstransferbankaccountTransit_DESC' | 'sElectronicfundstransferbankaccountInstitution_ASC' | 'sElectronicfundstransferbankaccountInstitution_DESC' | 'sElectronicfundstransferbankaccountAccount_ASC' | 'sElectronicfundstransferbankaccountAccount_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.supplierGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiSupplierID_ASC&#39; | &#39;pkiSupplierID_DESC&#39; | &#39;fkiPaymentmethodID_ASC&#39; | &#39;fkiPaymentmethodID_DESC&#39; | &#39;sSupplierName_ASC&#39; | &#39;sSupplierName_DESC&#39; | &#39;sSupplierCode_ASC&#39; | &#39;sSupplierCode_DESC&#39; | &#39;sSupplierAccount_ASC&#39; | &#39;sSupplierAccount_DESC&#39; | &#39;bSupplierIsactive_ASC&#39; | &#39;bSupplierIsactive_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39; | &#39;sPaymentmethodDescriptionX_ASC&#39; | &#39;sPaymentmethodDescriptionX_DESC&#39; | &#39;sElectronicfundstransferbankaccountTransit_ASC&#39; | &#39;sElectronicfundstransferbankaccountTransit_DESC&#39; | &#39;sElectronicfundstransferbankaccountInstitution_ASC&#39; | &#39;sElectronicfundstransferbankaccountInstitution_DESC&#39; | &#39;sElectronicfundstransferbankaccountAccount_ASC&#39; | &#39;sElectronicfundstransferbankaccountAccount_DESC&#39;**]**Array<&#39;pkiSupplierID_ASC&#39; &#124; &#39;pkiSupplierID_DESC&#39; &#124; &#39;fkiPaymentmethodID_ASC&#39; &#124; &#39;fkiPaymentmethodID_DESC&#39; &#124; &#39;sSupplierName_ASC&#39; &#124; &#39;sSupplierName_DESC&#39; &#124; &#39;sSupplierCode_ASC&#39; &#124; &#39;sSupplierCode_DESC&#39; &#124; &#39;sSupplierAccount_ASC&#39; &#124; &#39;sSupplierAccount_DESC&#39; &#124; &#39;bSupplierIsactive_ASC&#39; &#124; &#39;bSupplierIsactive_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39; &#124; &#39;sPaymentmethodDescriptionX_ASC&#39; &#124; &#39;sPaymentmethodDescriptionX_DESC&#39; &#124; &#39;sElectronicfundstransferbankaccountTransit_ASC&#39; &#124; &#39;sElectronicfundstransferbankaccountTransit_DESC&#39; &#124; &#39;sElectronicfundstransferbankaccountInstitution_ASC&#39; &#124; &#39;sElectronicfundstransferbankaccountInstitution_DESC&#39; &#124; &#39;sElectronicfundstransferbankaccountAccount_ASC&#39; &#124; &#39;sElectronicfundstransferbankaccountAccount_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**SupplierGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **supplierImportIntoEDMV1**
> SupplierImportIntoEDMV1Response supplierImportIntoEDMV1(supplierImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectSupplierApi,
    Configuration,
    SupplierImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectSupplierApi(configuration);

let pkiSupplierID: number; // (default to undefined)
let supplierImportIntoEDMV1Request: SupplierImportIntoEDMV1Request; //

const { status, data } = await apiInstance.supplierImportIntoEDMV1(
    pkiSupplierID,
    supplierImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **supplierImportIntoEDMV1Request** | **SupplierImportIntoEDMV1Request**|  | |
| **pkiSupplierID** | [**number**] |  | defaults to undefined|


### Return type

**SupplierImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

