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



import { DefaultObject } from '../base'

/**
 * Name of the Ezsignfoldertype
 * @export
 * @interface MultilingualEzsignfoldertypeName
 */
export interface MultilingualEzsignfoldertypeName {
    /**
     * The name of the Ezsignfoldertype in French
     * @type {string}
     * @memberof MultilingualEzsignfoldertypeName
     */
    'sEzsignfoldertypeName1'?: string;
    /**
     * The name of the Ezsignfoldertype in English
     * @type {string}
     * @memberof MultilingualEzsignfoldertypeName
     */
    'sEzsignfoldertypeName2'?: string;
}
/**
 * A MultilingualEzsignfoldertypeName Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectMultilingualEzsignfoldertypeName
 */
export class DefaultObjectMultilingualEzsignfoldertypeName extends DefaultObject {
   sEzsignfoldertypeName1?:string = undefined
   sEzsignfoldertypeName2?:string = undefined
}

