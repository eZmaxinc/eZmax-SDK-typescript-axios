/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureResponseCompound } from './ezsigntemplatesignature-response-compound';

/**
 * Payload for GET /2/object/ezsigntemplatesignature/{pkiEzsigntemplatesignatureID}
 * @export
 * @interface EzsigntemplatesignatureGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatesignatureGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatesignatureResponseCompound}
     * @memberof EzsigntemplatesignatureGetObjectV2ResponseMPayload
     */
    'objEzsigntemplatesignature': EzsigntemplatesignatureResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatesignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatesignatureResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload {
   objEzsigntemplatesignature:EzsigntemplatesignatureResponseCompound = new DataObjectEzsigntemplatesignatureResponseCompound()
}

/**
 * @export 
 * A EzsigntemplatesignatureGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplatesignatureGetObjectV2ResponseMPayload {
   objEzsigntemplatesignature = new ValidationObjectEzsigntemplatesignatureResponseCompound()
} 


