/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
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

import { DefaultObject } from '../base'

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
    'objEzsignfolder'?: EzsignfolderRequest;
    /**
     * 
     * @type {EzsignfolderRequestCompound}
     * @memberof EzsignfolderCreateObjectV1Request
     */
    'objEzsignfolderCompound'?: EzsignfolderRequestCompound;
}
/**
 * A EzsignfolderCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderCreateObjectV1Request
 */
export class DefaultObjectEzsignfolderCreateObjectV1Request extends DefaultObject {
   objEzsignfolder?:Partial<EzsignfolderRequest> = undefined
   objEzsignfolderCompound?:Partial<EzsignfolderRequestCompound> = undefined
}


