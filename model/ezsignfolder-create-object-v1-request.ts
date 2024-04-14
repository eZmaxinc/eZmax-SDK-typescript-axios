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
import { EzsignfolderRequest } from './ezsignfolder-request';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderRequestCompound } from './ezsignfolder-request-compound';

/**
 * Request for POST /1/object/ezsignfolder
 * @export
 * @interface EzsignfolderCreateObjectV1Request
 */
export interface EzsignfolderCreateObjectV1Request {
    /**
     * 
     * @type {EzsignfolderRequest}
     * @memberof EzsignfolderCreateObjectV1Request
     */
    /*'objEzsignfolder'?: EzsignfolderRequest;*/
    'objEzsignfolder'?: EzsignfolderRequest;
    /**
     * 
     * @type {EzsignfolderRequestCompound}
     * @memberof EzsignfolderCreateObjectV1Request
     */
    /*'objEzsignfolderCompound'?: EzsignfolderRequestCompound;*/
    'objEzsignfolderCompound'?: EzsignfolderRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignfolderRequest } from './'
// @ts-ignore
import { DataObjectEzsignfolderRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderRequest } from './'
// @ts-ignore
import { ValidationObjectEzsignfolderRequestCompound } from './'

/**
 * @export 
 * A EzsignfolderCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderCreateObjectV1Request
 */
export class DataObjectEzsignfolderCreateObjectV1Request {
   objEzsignfolder?:EzsignfolderRequest = undefined
   objEzsignfolderCompound?:EzsignfolderRequestCompound = undefined
}

/**
 * @export 
 * A EzsignfolderCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsignfolderCreateObjectV1Request
 */
export class ValidationObjectEzsignfolderCreateObjectV1Request {
   objEzsignfolder = new ValidationObjectEzsignfolderRequest()
   objEzsignfolderCompound = new ValidationObjectEzsignfolderRequestCompound()
} 


