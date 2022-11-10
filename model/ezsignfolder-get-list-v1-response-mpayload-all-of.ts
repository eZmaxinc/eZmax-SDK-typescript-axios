/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignfolderListElement } from './ezsignfolder-list-element';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsignfolderGetListV1ResponseMPayloadAllOf
 */
export interface EzsignfolderGetListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<EzsignfolderListElement>}
     * @memberof EzsignfolderGetListV1ResponseMPayloadAllOf
     */
    'a_objEzsignfolder': Array<EzsignfolderListElement>;
}
/**
 * A EzsignfolderGetListV1ResponseMPayloadAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsignfolderGetListV1ResponseMPayloadAllOf
 */
export class DefaultObjectEzsignfolderGetListV1ResponseMPayloadAllOf extends DefaultObject {
   a_objEzsignfolder:Array<EzsignfolderListElement> = []
}


