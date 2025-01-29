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
import type { EzsigntemplatesignatureRequestCompoundV2 } from './ezsigntemplatesignature-request-compound-v2';

/**
 * Request for PUT /2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 * @interface EzsigntemplatesignatureEditObjectV2Request
 */
export interface EzsigntemplatesignatureEditObjectV2Request {
    /**
     * 
     * @type {EzsigntemplatesignatureRequestCompoundV2}
     * @memberof EzsigntemplatesignatureEditObjectV2Request
     */
    /*'objEzsigntemplatesignature': EzsigntemplatesignatureRequestCompoundV2;*/
    'objEzsigntemplatesignature': EzsigntemplatesignatureRequestCompoundV2;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignatureRequestCompoundV2 } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureRequestCompoundV2 } from './'

/**
 * @export 
 * A EzsigntemplatesignatureEditObjectV2Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureEditObjectV2Request
 */
export class DataObjectEzsigntemplatesignatureEditObjectV2Request {
   objEzsigntemplatesignature:EzsigntemplatesignatureRequestCompoundV2 = new DataObjectEzsigntemplatesignatureRequestCompoundV2()
}

/**
 * @export 
 * A EzsigntemplatesignatureEditObjectV2Request Validation Object
 * @class ValidationObjectEzsigntemplatesignatureEditObjectV2Request
 */
export class ValidationObjectEzsigntemplatesignatureEditObjectV2Request {
   objEzsigntemplatesignature = new ValidationObjectEzsigntemplatesignatureRequestCompoundV2()
} 


