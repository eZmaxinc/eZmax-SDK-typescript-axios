/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponseCompound } from './ezsignsignature-response-compound';

/**
 * Payload for GET /2/object/ezsignsignature/{pkiEzsignsignatureID}
 * @export
 * @interface EzsignsignatureGetObjectV2ResponseMPayload
 */
export interface EzsignsignatureGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignsignatureResponseCompound}
     * @memberof EzsignsignatureGetObjectV2ResponseMPayload
     */
    /*'objEzsignsignature': EzsignsignatureResponseCompound;*/
    'objEzsignsignature': EzsignsignatureResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureResponseCompound } from './'

/**
 * @export 
 * A EzsignsignatureGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignsignatureGetObjectV2ResponseMPayload {
   objEzsignsignature:EzsignsignatureResponseCompound = new DataObjectEzsignsignatureResponseCompound()
}

/**
 * @export 
 * A EzsignsignatureGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignsignatureGetObjectV2ResponseMPayload {
   objEzsignsignature = new ValidationObjectEzsignsignatureResponseCompound()
} 


