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



import { DefaultObject } from '../base'

/**
 * A Ezsigntemplatepackage Object
 * @export
 * @interface EzsigntemplatepackageResponse
 */
export interface EzsigntemplatepackageResponse {
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageResponse
     */
    'pkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepackageResponse
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplatepackageResponse
     */
    'fkiLanguageID': number;
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageResponse
     */
    'sLanguageNameX': string;
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageResponse
     */
    'sEzsigntemplatepackageDescription': string;
    /**
     * Whether the Ezsigntemplatepackage can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponse
     */
    'bEzsigntemplatepackageAdminonly': boolean;
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponse
     */
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponse
     */
    'bEzsigntemplatepackageIsactive': boolean;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageResponse
     */
    'sEzsignfoldertypeNameX': string;
}
/**
 * A EzsigntemplatepackageResponse Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageResponse
 */
export class DefaultObjectEzsigntemplatepackageResponse extends DefaultObject {
   pkiEzsigntemplatepackageID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sLanguageNameX:string = ''
   sEzsigntemplatepackageDescription:string = ''
   bEzsigntemplatepackageAdminonly:boolean = false
   bEzsigntemplatepackageNeedvalidation:boolean = false
   bEzsigntemplatepackageIsactive:boolean = false
   sEzsignfoldertypeNameX:string = ''
}


