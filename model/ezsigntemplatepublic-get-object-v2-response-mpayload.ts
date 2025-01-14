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
import { EzsigntemplatepublicResponseCompound } from './ezsigntemplatepublic-response-compound';

/**
 * Payload for GET /2/object/ezsigntemplatepublic/{pkiEzsigntemplatepublicID}
 * @export
 * @interface EzsigntemplatepublicGetObjectV2ResponseMPayload
 */
export interface EzsigntemplatepublicGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigntemplatepublicResponseCompound}
     * @memberof EzsigntemplatepublicGetObjectV2ResponseMPayload
     */
    /*'objEzsigntemplatepublic': EzsigntemplatepublicResponseCompound;*/
    'objEzsigntemplatepublic': EzsigntemplatepublicResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepublicResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepublicResponseCompound } from './'

/**
 * @export 
 * A EzsigntemplatepublicGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepublicGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigntemplatepublicGetObjectV2ResponseMPayload {
   objEzsigntemplatepublic:EzsigntemplatepublicResponseCompound = new DataObjectEzsigntemplatepublicResponseCompound()
}

/**
 * @export 
 * A EzsigntemplatepublicGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigntemplatepublicGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigntemplatepublicGetObjectV2ResponseMPayload {
   objEzsigntemplatepublic = new ValidationObjectEzsigntemplatepublicResponseCompound()
} 


