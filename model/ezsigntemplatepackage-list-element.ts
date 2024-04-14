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
    /*'pkiEzsigntemplatepackageID': number;*/
    'pkiEzsigntemplatepackageID': number;
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'fkiEzsignfoldertypeID': number;*/
    'fkiEzsignfoldertypeID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'fkiLanguageID': number;*/
    'fkiLanguageID': number;
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'sEzsigntemplatepackageDescription': string;*/
    'sEzsigntemplatepackageDescription': string;
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'bEzsigntemplatepackageNeedvalidation': boolean;*/
    'bEzsigntemplatepackageNeedvalidation': boolean;
    /**
     * The total number of Ezsigntemplatepackagemembership in the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'iEzsigntemplatepackagemembership': number;*/
    'iEzsigntemplatepackagemembership': number;
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'sEzsignfoldertypeNameX': string;*/
    'sEzsignfoldertypeNameX': string;
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageListElement
     */
    /*'bEzsigntemplatepackageIsactive': boolean;*/
    'bEzsigntemplatepackageIsactive': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageListElement
 */
export class DataObjectEzsigntemplatepackageListElement {
   pkiEzsigntemplatepackageID:number = 0
   fkiEzsignfoldertypeID:number = 0
   fkiLanguageID:number = 0
   sEzsigntemplatepackageDescription:string = ''
   bEzsigntemplatepackageNeedvalidation:boolean = false
   iEzsigntemplatepackagemembership:number = 0
   sEzsignfoldertypeNameX:string = ''
   bEzsigntemplatepackageIsactive:boolean = false
}

/**
 * @export 
 * A EzsigntemplatepackageListElement Validation Object
 * @class ValidationObjectEzsigntemplatepackageListElement
 */
export class ValidationObjectEzsigntemplatepackageListElement {
   pkiEzsigntemplatepackageID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiEzsignfoldertypeID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sEzsigntemplatepackageDescription = {
      type: 'string',
      required: true
   }
   bEzsigntemplatepackageNeedvalidation = {
      type: 'boolean',
      required: true
   }
   iEzsigntemplatepackagemembership = {
      type: 'integer',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   bEzsigntemplatepackageIsactive = {
      type: 'boolean',
      required: true
   }
} 


