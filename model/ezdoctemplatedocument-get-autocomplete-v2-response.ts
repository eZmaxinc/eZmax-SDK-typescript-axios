/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponse } from './common-response';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebug } from './common-response-obj-debug';
// May contain unused imports in some cases
// @ts-ignore
import type { CommonResponseObjDebugPayload } from './common-response-obj-debug-payload';
// May contain unused imports in some cases
// @ts-ignore
import type { EzdoctemplatedocumentGetAutocompleteV2ResponseMPayload } from './ezdoctemplatedocument-get-autocomplete-v2-response-mpayload';

/**
 * @type EzdoctemplatedocumentGetAutocompleteV2Response
 * Response for GET /2/object/ezdoctemplatedocument/getAutocomplete
 * @export
 */
/*export type EzdoctemplatedocumentGetAutocompleteV2Response = CommonResponse;*/
export interface EzdoctemplatedocumentGetAutocompleteV2Response {
    /**
     * 
     * @type {EzdoctemplatedocumentGetAutocompleteV2ResponseMPayload}
     * @memberof EzdoctemplatedocumentGetAutocompleteV2Response
     */
    mPayload:EzdoctemplatedocumentGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzdoctemplatedocumentGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectEzdoctemplatedocumentGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A EzdoctemplatedocumentGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzdoctemplatedocumentGetAutocompleteV2Response
 */
export class DataObjectEzdoctemplatedocumentGetAutocompleteV2Response {
    mPayload:EzdoctemplatedocumentGetAutocompleteV2ResponseMPayload = new DataObjectEzdoctemplatedocumentGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A EzdoctemplatedocumentGetAutocompleteV2Response Validation Object
 * @class ValidationObjectEzdoctemplatedocumentGetAutocompleteV2Response
 */
export class ValidationObjectEzdoctemplatedocumentGetAutocompleteV2Response {
   mPayload = new ValidationObjectEzdoctemplatedocumentGetAutocompleteV2ResponseMPayload()
} 


