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
import type { EzsignuserResponseCompound } from './ezsignuser-response-compound';

/**
 * Payload for GET /2/object/ezsignuser/{pkiEzsignuserID}
 * @export
 * @interface EzsignuserGetObjectV2ResponseMPayload
 */
export interface EzsignuserGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignuserResponseCompound}
     * @memberof EzsignuserGetObjectV2ResponseMPayload
     */
    /*'objEzsignuser': EzsignuserResponseCompound;*/
    'objEzsignuser': EzsignuserResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignuserResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignuserResponseCompound } from './'

/**
 * @export 
 * A EzsignuserGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignuserGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignuserGetObjectV2ResponseMPayload {
   objEzsignuser:EzsignuserResponseCompound = new DataObjectEzsignuserResponseCompound()
}

/**
 * @export 
 * A EzsignuserGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignuserGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignuserGetObjectV2ResponseMPayload {
   objEzsignuser = new ValidationObjectEzsignuserResponseCompound()
} 


