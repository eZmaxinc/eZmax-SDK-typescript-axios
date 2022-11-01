/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.14
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
 * @interface EzsigntemplateRequest
 */
export interface EzsigntemplateRequest {
    /**
     * The unique ID of the Ezsigntemplate
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    'pkiEzsigntemplateID'?: number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplateRequest
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplate
     * @type {string}
     * @memberof EzsigntemplateRequest
     */
    'sEzsigntemplateDescription': string;
    /**
     * Whether the Ezsigntemplate can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplateRequest
     */
    'bEzsigntemplateAdminonly': boolean;
}
/**
 * A EzsigntemplateRequest Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplateRequest
 */
export class DefaultObjectEzsigntemplateRequest extends DefaultObject {
   pkiEzsigntemplateID?:number = undefined
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplateDescription:string = ''
   bEzsigntemplateAdminonly:boolean = false
}


