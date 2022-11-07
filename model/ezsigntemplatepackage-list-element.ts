/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



import { DefaultObject } from '../base'

/**
 * An Ezsigntemplatepackage List Element
 * @export
 * @interface EzsigntemplatepackageListElement
 */
export interface EzsigntemplatepackageListElement {
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    'pkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageListElement
     */
    'sEzsigntemplatepackageDescription': string;
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackageListElement
     */
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * The total number of Ezsigntemplatepackagemembership in the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    'iEzsigntemplatepackagemembership': number;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageListElement
     */
    'sEzsignfoldertypeNameX': string;
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageListElement
     */
    'bEzsigntemplatepackageIsactive': boolean;
}
/**
 * A EzsigntemplatepackageListElement Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigntemplatepackageListElement
 */
export class DefaultObjectEzsigntemplatepackageListElement extends DefaultObject {
   pkiEzsigntemplatepackageID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplatepackageDescription:string = ''
   bEzsigntemplatepackageNeedvalidation:boolean = false
   iEzsigntemplatepackagemembership:number = 0
   sEzsignfoldertypeNameX:string = ''
   bEzsigntemplatepackageIsactive:boolean = false
}


