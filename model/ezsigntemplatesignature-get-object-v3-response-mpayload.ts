/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatesignatureResponseCompoundV3 } from './ezsigntemplatesignature-response-compound-v3';

/**
 * Payload for GET /3/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 * @interface EzsigntemplatesignatureGetObjectV3ResponseMPayload
 */
export interface EzsigntemplatesignatureGetObjectV3ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatesignatureResponseCompoundV3}
     * @memberof EzsigntemplatesignatureGetObjectV3ResponseMPayload
     */
    /*'objEzsigntemplatesignature': EzsigntemplatesignatureResponseCompoundV3;*/
    'objEzsigntemplatesignature': EzsigntemplatesignatureResponseCompoundV3;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignatureResponseCompoundV3 } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureResponseCompoundV3 } from './'

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV3ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureGetObjectV3ResponseMPayload
 */
export class DataObjectEzsigntemplatesignatureGetObjectV3ResponseMPayload {
   objEzsigntemplatesignature:EzsigntemplatesignatureResponseCompoundV3 = new DataObjectEzsigntemplatesignatureResponseCompoundV3()
}

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV3ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatesignatureGetObjectV3ResponseMPayload
 */
export class ValidationObjectEzsigntemplatesignatureGetObjectV3ResponseMPayload {
   objEzsigntemplatesignature = new ValidationObjectEzsigntemplatesignatureResponseCompoundV3()
} 


