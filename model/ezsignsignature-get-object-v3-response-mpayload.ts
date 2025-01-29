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
import type { EzsignsignatureResponseCompoundV3 } from './ezsignsignature-response-compound-v3';

/**
 * Payload for GET /3/object/ezsignsignature/{pkiEzsignsignatureID}
 * @export
 * @interface EzsignsignatureGetObjectV3ResponseMPayload
 */
export interface EzsignsignatureGetObjectV3ResponseMPayload {
    /**
     * 
     * @type {EzsignsignatureResponseCompoundV3}
     * @memberof EzsignsignatureGetObjectV3ResponseMPayload
     */
    /*'objEzsignsignature': EzsignsignatureResponseCompoundV3;*/
    'objEzsignsignature': EzsignsignatureResponseCompoundV3;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignsignatureResponseCompoundV3 } from './'
// @ts-ignore
import { ValidationObjectEzsignsignatureResponseCompoundV3 } from './'

/**
 * @export 
 * A EzsignsignatureGetObjectV3ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignsignatureGetObjectV3ResponseMPayload
 */
export class DataObjectEzsignsignatureGetObjectV3ResponseMPayload {
   objEzsignsignature:EzsignsignatureResponseCompoundV3 = new DataObjectEzsignsignatureResponseCompoundV3()
}

/**
 * @export 
 * A EzsignsignatureGetObjectV3ResponseMPayload Validation Object
 * @class ValidationObjectEzsignsignatureGetObjectV3ResponseMPayload
 */
export class ValidationObjectEzsignsignatureGetObjectV3ResponseMPayload {
   objEzsignsignature = new ValidationObjectEzsignsignatureResponseCompoundV3()
} 


