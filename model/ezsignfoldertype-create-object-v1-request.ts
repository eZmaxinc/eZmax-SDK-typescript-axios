/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.11
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfoldertypeRequestCompound } from './ezsignfoldertype-request-compound';

import { DefaultObject } from '../base'

/**
 * Request for POST /1/object/ezsignfoldertype
 * @export
 * @interface EzsignfoldertypeCreateObjectV1Request
 */
export interface EzsignfoldertypeCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignfoldertypeRequestCompound>}
     * @memberof EzsignfoldertypeCreateObjectV1Request
     */
    'a_objEzsignfoldertype': Array<EzsignfoldertypeRequestCompound>;
}
/**
 * A EzsignfoldertypeCreateObjectV1Request Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfoldertypeCreateObjectV1Request
 */
export class DefaultObjectEzsignfoldertypeCreateObjectV1Request extends DefaultObject {
   a_objEzsignfoldertype:Array<EzsignfoldertypeRequestCompound> = []
}


