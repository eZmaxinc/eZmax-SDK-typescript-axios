# ObjectCustomerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**customerCreateObjectV1**](#customercreateobjectv1) | **POST** /1/object/customer | Create a new Customer|
|[**customerGetAutocompleteV2**](#customergetautocompletev2) | **GET** /2/object/customer/getAutocomplete/{sSelector} | Retrieve Customers and IDs|
|[**customerGetListV1**](#customergetlistv1) | **GET** /1/object/customer/getList | Retrieve Customer list|
|[**customerGetObjectV2**](#customergetobjectv2) | **GET** /2/object/customer/{pkiCustomerID} | Retrieve an existing Customer|
|[**customerImportIntoEDMV1**](#customerimportintoedmv1) | **POST** /1/object/customer/{pkiCustomerID}/importIntoEDM | Import attachments into the Buyercontract|

# **customerCreateObjectV1**
> CustomerCreateObjectV1Response customerCreateObjectV1(customerCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration,
    CustomerCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let customerCreateObjectV1Request: CustomerCreateObjectV1Request; //

const { status, data } = await apiInstance.customerCreateObjectV1(
    customerCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **customerCreateObjectV1Request** | **CustomerCreateObjectV1Request**|  | |


### Return type

**CustomerCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **customerGetAutocompleteV2**
> CustomerGetAutocompleteV2Response customerGetAutocompleteV2()

Get the list of Customer to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let sSelector: 'All'; //The type of Customers to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.customerGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Customers to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**CustomerGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **customerGetListV1**
> CustomerGetListV1Response customerGetListV1()



### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let eOrderBy: 'pkiCustomerID_ASC' | 'pkiCustomerID_DESC' | 'sCustomerName_ASC' | 'sCustomerName_DESC' | 'sCustomerNote_ASC' | 'sCustomerNote_DESC' | 'sCustomerCode_ASC' | 'sCustomerCode_DESC' | 'bCustomerIsactive_ASC' | 'bCustomerIsactive_DESC' | 'sPhoneE164_ASC' | 'sPhoneE164_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.customerGetListV1(
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
| **eOrderBy** | [**&#39;pkiCustomerID_ASC&#39; | &#39;pkiCustomerID_DESC&#39; | &#39;sCustomerName_ASC&#39; | &#39;sCustomerName_DESC&#39; | &#39;sCustomerNote_ASC&#39; | &#39;sCustomerNote_DESC&#39; | &#39;sCustomerCode_ASC&#39; | &#39;sCustomerCode_DESC&#39; | &#39;bCustomerIsactive_ASC&#39; | &#39;bCustomerIsactive_DESC&#39; | &#39;sPhoneE164_ASC&#39; | &#39;sPhoneE164_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39;**]**Array<&#39;pkiCustomerID_ASC&#39; &#124; &#39;pkiCustomerID_DESC&#39; &#124; &#39;sCustomerName_ASC&#39; &#124; &#39;sCustomerName_DESC&#39; &#124; &#39;sCustomerNote_ASC&#39; &#124; &#39;sCustomerNote_DESC&#39; &#124; &#39;sCustomerCode_ASC&#39; &#124; &#39;sCustomerCode_DESC&#39; &#124; &#39;bCustomerIsactive_ASC&#39; &#124; &#39;bCustomerIsactive_DESC&#39; &#124; &#39;sPhoneE164_ASC&#39; &#124; &#39;sPhoneE164_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**CustomerGetListV1Response**

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

# **customerGetObjectV2**
> CustomerGetObjectV2Response customerGetObjectV2()



### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let pkiCustomerID: number; //The unique ID of the Customer (default to undefined)

const { status, data } = await apiInstance.customerGetObjectV2(
    pkiCustomerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCustomerID** | [**number**] | The unique ID of the Customer | defaults to undefined|


### Return type

**CustomerGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **customerImportIntoEDMV1**
> CustomerImportIntoEDMV1Response customerImportIntoEDMV1(customerImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectCustomerApi,
    Configuration,
    CustomerImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCustomerApi(configuration);

let pkiCustomerID: number; // (default to undefined)
let customerImportIntoEDMV1Request: CustomerImportIntoEDMV1Request; //

const { status, data } = await apiInstance.customerImportIntoEDMV1(
    pkiCustomerID,
    customerImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **customerImportIntoEDMV1Request** | **CustomerImportIntoEDMV1Request**|  | |
| **pkiCustomerID** | [**number**] |  | defaults to undefined|


### Return type

**CustomerImportIntoEDMV1Response**

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

