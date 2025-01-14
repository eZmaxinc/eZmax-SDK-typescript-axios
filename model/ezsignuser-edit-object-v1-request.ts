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
import { EzsignuserRequestCompound } from './ezsignuser-request-compound';

/**
 * Request for PUT /1/object/ezsignuser/{pkiEzsignuserID}
 * @export
 * @interface EzsignuserEditObjectV1Request
 */
export interface EzsignuserEditObjectV1Request {
    /**
     * 
     * @type {EzsignuserRequestCompound}
     * @memberof EzsignuserEditObjectV1Request
     */
    /*'objEzsignuser': EzsignuserRequestCompound;*/
    'objEzsignuser': EzsignuserRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignuserRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignuserRequestCompound } from './'

/**
 * @export 
 * A EzsignuserEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignuserEditObjectV1Request
 */
export class DataObjectEzsignuserEditObjectV1Request {
   objEzsignuser:EzsignuserRequestCompound = new DataObjectEzsignuserRequestCompound()
}

/**
 * @export 
 * A EzsignuserEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignuserEditObjectV1Request
 */
export class ValidationObjectEzsignuserEditObjectV1Request {
   objEzsignuser = new ValidationObjectEzsignuserRequestCompound()
} 


