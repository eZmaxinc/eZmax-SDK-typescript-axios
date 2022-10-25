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
 * A Ezsigntemplate Object
 * @export
 * @interface EzsigntemplateResponse
 */
export interface EzsigntemplateResponse {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'pkiEzsigntemplateID': number;
    /**
     * The unique ID of the Ezsigntemplatedocument
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiEzsigntemplatedocumentID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateResponse
     */
    'fkiLanguageID': number;
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sLanguageNameX': string;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sEzsigntemplateDescription': string;
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateResponse
     */
    'bEzsigntemplateAdminonly': boolean;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplateResponse
     */
    'sEzsignfoldertypeNameX': string;
}
/**
 * A EzsigntemplateResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateResponse
 */
export class DefaultObjectEzsigntemplateResponse extends DefaultObject {
   pkiEzsigntemplateID:number = 0
   fkiEzsigntemplatedocumentID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   sEzsigntemplateDescription:string = ''
   bEzsigntemplateAdminonly:boolean = false
   sEzsignfoldertypeNameX:string = ''
}


