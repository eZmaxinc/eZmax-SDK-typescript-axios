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
import type { PeriodGetAutocompleteV2ResponseMPayload } from './period-get-autocomplete-v2-response-mpayload';

/**
 * @type PeriodGetAutocompleteV2Response
 * Response for GET /2/object/period/getAutocomplete
 * @export
 */
/*export type PeriodGetAutocompleteV2Response = CommonResponse;*/
export interface PeriodGetAutocompleteV2Response {
    /**
     * 
     * @type {PeriodGetAutocompleteV2ResponseMPayload}
     * @memberof PeriodGetAutocompleteV2Response
     */
    mPayload:PeriodGetAutocompleteV2ResponseMPayload 
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectPeriodGetAutocompleteV2ResponseMPayload } from './'
// @ts-ignore
import { ValidationObjectPeriodGetAutocompleteV2ResponseMPayload } from './'

/**
 * @export 
 * A PeriodGetAutocompleteV2Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectPeriodGetAutocompleteV2Response
 */
export class DataObjectPeriodGetAutocompleteV2Response {
    mPayload:PeriodGetAutocompleteV2ResponseMPayload = new DataObjectPeriodGetAutocompleteV2ResponseMPayload()
}

/**
 * @export 
 * A PeriodGetAutocompleteV2Response Validation Object
 * @class ValidationObjectPeriodGetAutocompleteV2Response
 */
export class ValidationObjectPeriodGetAutocompleteV2Response {
   mPayload = new ValidationObjectPeriodGetAutocompleteV2ResponseMPayload()
} 


