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
import { EzsignfolderRequestCompound } from './ezsignfolder-request-compound';

/**
 * Request for PUT /1/object/ezsignfolder/{pkiEzsignfolderID}
 * @export
 * @interface EzsignfolderEditObjectV1Request
 */
export interface EzsignfolderEditObjectV1Request {
    /**
     * 
     * @type {EzsignfolderRequestCompound}
     * @memberof EzsignfolderEditObjectV1Request
     */
    'objEzsignfolder': EzsignfolderRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderRequestCompound } from './'

/**
 * @export 
 * A EzsignfolderEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderEditObjectV1Request
 */
export class DataObjectEzsignfolderEditObjectV1Request {
   objEzsignfolder:EzsignfolderRequestCompound = new DataObjectEzsignfolderRequestCompound()
}

/**
 * @export 
 * A EzsignfolderEditObjectV1Request Validation Object
 * @class ValidationObjectEzsignfolderEditObjectV1Request
 */
export class ValidationObjectEzsignfolderEditObjectV1Request {
   objEzsignfolder = new ValidationObjectEzsignfolderRequestCompound()
} 


