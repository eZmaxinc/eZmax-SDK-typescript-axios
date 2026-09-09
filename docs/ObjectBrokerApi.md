# ObjectBrokerApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**brokerBatchDownloadV1**](#brokerbatchdownloadv1) | **POST** /1/object/broker/{pkiBrokerID}/batchDownload | Download multiples attachments from a Broker|
|[**brokerGetAttachmentsV1**](#brokergetattachmentsv1) | **GET** /1/object/broker/{pkiBrokerID}/getAttachments | Retrieve Broker\&#39;s attachments|
|[**brokerGetAutocompleteV2**](#brokergetautocompletev2) | **GET** /2/object/broker/getAutocomplete/{sSelector} | Retrieve Brokers and IDs|
|[**brokerGetListV1**](#brokergetlistv1) | **GET** /1/object/broker/getList | Retrieve Broker list|
|[**brokerImportIntoEDMV1**](#brokerimportintoedmv1) | **POST** /1/object/broker/{pkiBrokerID}/importIntoEDM | Import attachments into the Broker|

# **brokerBatchDownloadV1**
> File brokerBatchDownloadV1(brokerBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectBrokerApi,
    Configuration,
    BrokerBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrokerApi(configuration);

let pkiBrokerID: number; // (default to undefined)
let brokerBatchDownloadV1Request: BrokerBatchDownloadV1Request; //

const { status, data } = await apiInstance.brokerBatchDownloadV1(
    pkiBrokerID,
    brokerBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **brokerBatchDownloadV1Request** | **BrokerBatchDownloadV1Request**|  | |
| **pkiBrokerID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **brokerGetAttachmentsV1**
> BrokerGetAttachmentsV1Response brokerGetAttachmentsV1()


### Example

```typescript
import {
    ObjectBrokerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrokerApi(configuration);

let pkiBrokerID: number; // (default to undefined)

const { status, data } = await apiInstance.brokerGetAttachmentsV1(
    pkiBrokerID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBrokerID** | [**number**] |  | defaults to undefined|


### Return type

**BrokerGetAttachmentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **brokerGetAutocompleteV2**
> BrokerGetAutocompleteV2Response brokerGetAutocompleteV2()

Get the list of Broker to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectBrokerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrokerApi(configuration);

let sSelector: 'All'; //The type of Brokers to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.brokerGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Brokers to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**BrokerGetAutocompleteV2Response**

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

# **brokerGetListV1**
> BrokerGetListV1Response brokerGetListV1()



### Example

```typescript
import {
    ObjectBrokerApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrokerApi(configuration);

let eOrderBy: 'pkiBrokerID_ASC' | 'pkiBrokerID_DESC' | 'fkiDepartmentID_ASC' | 'fkiDepartmentID_DESC' | 'sDepartmentNameX_ASC' | 'sDepartmentNameX_DESC' | 'sLanguageNameX_ASC' | 'sLanguageNameX_DESC' | 'fkiBrokertypeID_ASC' | 'fkiBrokertypeID_DESC' | 'sBrokertypeNameX_ASC' | 'sBrokertypeNameX_DESC' | 'sRealestateboardnumberNumber_ASC' | 'sRealestateboardnumberNumber_DESC' | 'sBrokerCode_ASC' | 'sBrokerCode_DESC' | 'iBrokerPhotocopiercode_ASC' | 'iBrokerPhotocopiercode_DESC' | 'iBrokerLongdistancecode_ASC' | 'iBrokerLongdistancecode_DESC' | 'sBrokerName_ASC' | 'sBrokerName_DESC' | 'iAgentBannernumber_ASC' | 'iAgentBannernumber_DESC' | 'sBrokerRealestateassociationlicense_ASC' | 'sBrokerRealestateassociationlicense_DESC' | 'dtBrokerHiredate_ASC' | 'dtBrokerHiredate_DESC' | 'dtBrokerLeavedate_ASC' | 'dtBrokerLeavedate_DESC' | 'bBrokerTranquillit_ASC' | 'bBrokerTranquillit_DESC' | 'bBrokerResidentiallicense_ASC' | 'bBrokerResidentiallicense_DESC' | 'bBrokerCommerciallicense_ASC' | 'bBrokerCommerciallicense_DESC' | 'bBrokerMortgagelicense_ASC' | 'bBrokerMortgagelicense_DESC' | 'bBrokerPaidbyofficetranquillit_ASC' | 'bBrokerPaidbyofficetranquillit_DESC' | 'dtBrokerFintraccertification_ASC' | 'dtBrokerFintraccertification_DESC' | 'sContactFirstname_ASC' | 'sContactFirstname_DESC' | 'sContactLastname_ASC' | 'sContactLastname_DESC' | 'dtContactBirthdate_ASC' | 'dtContactBirthdate_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sPhoneE164_ASC' | 'sPhoneE164_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC' | 'bBrokerIsactive_ASC' | 'bBrokerIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.brokerGetListV1(
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
| **eOrderBy** | [**&#39;pkiBrokerID_ASC&#39; | &#39;pkiBrokerID_DESC&#39; | &#39;fkiDepartmentID_ASC&#39; | &#39;fkiDepartmentID_DESC&#39; | &#39;sDepartmentNameX_ASC&#39; | &#39;sDepartmentNameX_DESC&#39; | &#39;sLanguageNameX_ASC&#39; | &#39;sLanguageNameX_DESC&#39; | &#39;fkiBrokertypeID_ASC&#39; | &#39;fkiBrokertypeID_DESC&#39; | &#39;sBrokertypeNameX_ASC&#39; | &#39;sBrokertypeNameX_DESC&#39; | &#39;sRealestateboardnumberNumber_ASC&#39; | &#39;sRealestateboardnumberNumber_DESC&#39; | &#39;sBrokerCode_ASC&#39; | &#39;sBrokerCode_DESC&#39; | &#39;iBrokerPhotocopiercode_ASC&#39; | &#39;iBrokerPhotocopiercode_DESC&#39; | &#39;iBrokerLongdistancecode_ASC&#39; | &#39;iBrokerLongdistancecode_DESC&#39; | &#39;sBrokerName_ASC&#39; | &#39;sBrokerName_DESC&#39; | &#39;iAgentBannernumber_ASC&#39; | &#39;iAgentBannernumber_DESC&#39; | &#39;sBrokerRealestateassociationlicense_ASC&#39; | &#39;sBrokerRealestateassociationlicense_DESC&#39; | &#39;dtBrokerHiredate_ASC&#39; | &#39;dtBrokerHiredate_DESC&#39; | &#39;dtBrokerLeavedate_ASC&#39; | &#39;dtBrokerLeavedate_DESC&#39; | &#39;bBrokerTranquillit_ASC&#39; | &#39;bBrokerTranquillit_DESC&#39; | &#39;bBrokerResidentiallicense_ASC&#39; | &#39;bBrokerResidentiallicense_DESC&#39; | &#39;bBrokerCommerciallicense_ASC&#39; | &#39;bBrokerCommerciallicense_DESC&#39; | &#39;bBrokerMortgagelicense_ASC&#39; | &#39;bBrokerMortgagelicense_DESC&#39; | &#39;bBrokerPaidbyofficetranquillit_ASC&#39; | &#39;bBrokerPaidbyofficetranquillit_DESC&#39; | &#39;dtBrokerFintraccertification_ASC&#39; | &#39;dtBrokerFintraccertification_DESC&#39; | &#39;sContactFirstname_ASC&#39; | &#39;sContactFirstname_DESC&#39; | &#39;sContactLastname_ASC&#39; | &#39;sContactLastname_DESC&#39; | &#39;dtContactBirthdate_ASC&#39; | &#39;dtContactBirthdate_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sPhoneE164_ASC&#39; | &#39;sPhoneE164_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39; | &#39;bBrokerIsactive_ASC&#39; | &#39;bBrokerIsactive_DESC&#39;**]**Array<&#39;pkiBrokerID_ASC&#39; &#124; &#39;pkiBrokerID_DESC&#39; &#124; &#39;fkiDepartmentID_ASC&#39; &#124; &#39;fkiDepartmentID_DESC&#39; &#124; &#39;sDepartmentNameX_ASC&#39; &#124; &#39;sDepartmentNameX_DESC&#39; &#124; &#39;sLanguageNameX_ASC&#39; &#124; &#39;sLanguageNameX_DESC&#39; &#124; &#39;fkiBrokertypeID_ASC&#39; &#124; &#39;fkiBrokertypeID_DESC&#39; &#124; &#39;sBrokertypeNameX_ASC&#39; &#124; &#39;sBrokertypeNameX_DESC&#39; &#124; &#39;sRealestateboardnumberNumber_ASC&#39; &#124; &#39;sRealestateboardnumberNumber_DESC&#39; &#124; &#39;sBrokerCode_ASC&#39; &#124; &#39;sBrokerCode_DESC&#39; &#124; &#39;iBrokerPhotocopiercode_ASC&#39; &#124; &#39;iBrokerPhotocopiercode_DESC&#39; &#124; &#39;iBrokerLongdistancecode_ASC&#39; &#124; &#39;iBrokerLongdistancecode_DESC&#39; &#124; &#39;sBrokerName_ASC&#39; &#124; &#39;sBrokerName_DESC&#39; &#124; &#39;iAgentBannernumber_ASC&#39; &#124; &#39;iAgentBannernumber_DESC&#39; &#124; &#39;sBrokerRealestateassociationlicense_ASC&#39; &#124; &#39;sBrokerRealestateassociationlicense_DESC&#39; &#124; &#39;dtBrokerHiredate_ASC&#39; &#124; &#39;dtBrokerHiredate_DESC&#39; &#124; &#39;dtBrokerLeavedate_ASC&#39; &#124; &#39;dtBrokerLeavedate_DESC&#39; &#124; &#39;bBrokerTranquillit_ASC&#39; &#124; &#39;bBrokerTranquillit_DESC&#39; &#124; &#39;bBrokerResidentiallicense_ASC&#39; &#124; &#39;bBrokerResidentiallicense_DESC&#39; &#124; &#39;bBrokerCommerciallicense_ASC&#39; &#124; &#39;bBrokerCommerciallicense_DESC&#39; &#124; &#39;bBrokerMortgagelicense_ASC&#39; &#124; &#39;bBrokerMortgagelicense_DESC&#39; &#124; &#39;bBrokerPaidbyofficetranquillit_ASC&#39; &#124; &#39;bBrokerPaidbyofficetranquillit_DESC&#39; &#124; &#39;dtBrokerFintraccertification_ASC&#39; &#124; &#39;dtBrokerFintraccertification_DESC&#39; &#124; &#39;sContactFirstname_ASC&#39; &#124; &#39;sContactFirstname_DESC&#39; &#124; &#39;sContactLastname_ASC&#39; &#124; &#39;sContactLastname_DESC&#39; &#124; &#39;dtContactBirthdate_ASC&#39; &#124; &#39;dtContactBirthdate_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sPhoneE164_ASC&#39; &#124; &#39;sPhoneE164_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39; &#124; &#39;bBrokerIsactive_ASC&#39; &#124; &#39;bBrokerIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**BrokerGetListV1Response**

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

# **brokerImportIntoEDMV1**
> BrokerImportIntoEDMV1Response brokerImportIntoEDMV1(brokerImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectBrokerApi,
    Configuration,
    BrokerImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBrokerApi(configuration);

let pkiBrokerID: number; // (default to undefined)
let brokerImportIntoEDMV1Request: BrokerImportIntoEDMV1Request; //

const { status, data } = await apiInstance.brokerImportIntoEDMV1(
    pkiBrokerID,
    brokerImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **brokerImportIntoEDMV1Request** | **BrokerImportIntoEDMV1Request**|  | |
| **pkiBrokerID** | [**number**] |  | defaults to undefined|


### Return type

**BrokerImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

