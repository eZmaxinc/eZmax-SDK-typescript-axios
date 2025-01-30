/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackageResponse } from './ezsigntemplatepackage-response';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackagemembershipResponseCompound } from './ezsigntemplatepackagemembership-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import type { EzsigntemplatepackagesignerResponseCompound } from './ezsigntemplatepackagesigner-response-compound';

/**
 * @type EzsigntemplatepackageResponseCompound
 * A Ezsigntemplatepackage Object
 * @export
 */
/*export type EzsigntemplatepackageResponseCompound = EzsigntemplatepackageResponse;*/
export interface EzsigntemplatepackageResponseCompound {
    /**
     * The unique ID of the Ezsigntemplatepackage
     * @type {number}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    pkiEzsigntemplatepackageID:number 
    /**
     * The unique ID of the Ezsignfoldertype.
     * @type {number}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    fkiEzsignfoldertypeID:number 
    /**
     * The unique ID of the Ezdoctemplatedocument
     * @type {number}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    fkiEzdoctemplatedocumentID?:number 
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    fkiLanguageID:number 
    /**
     * The name of the Ezdoctemplatedocument in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    sEzdoctemplatedocumentNameX?:string 
    /**
     * The Name of the Language in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    sLanguageNameX:string 
    /**
     * The description of the Ezsigntemplatepackage
     * @type {string}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    sEzsigntemplatepackageDescription:string 
    /**
     * Whether the Ezsigntemplatepackage can be accessed by admin users only (eUserType=Normal)
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    bEzsigntemplatepackageAdminonly:boolean 
    /**
     * Whether the Ezsignbulksend was automatically modified and needs a manual validation
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    bEzsigntemplatepackageNeedvalidation:boolean 
    /**
     * Whether the Ezsigntemplatepackage is active or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    bEzsigntemplatepackageIsactive:boolean 
    /**
     * The name of the Ezsignfoldertype in the language of the requester
     * @type {string}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    sEzsignfoldertypeNameX:string 
    /**
     * Whether the Ezsigntemplatepackage if allowed to edit or not
     * @type {boolean}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    bEzsigntemplatepackageEditallowed:boolean 
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignerResponseCompound>}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerResponseCompound> 
    /**
     * 
     * @type {Array<EzsigntemplatepackagemembershipResponseCompound>}
     * @memberof EzsigntemplatepackageResponseCompound
     */
    a_objEzsigntemplatepackagemembership:Array<EzsigntemplatepackagemembershipResponseCompound> 
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackageResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackageResponseCompound
 */
export class DataObjectEzsigntemplatepackageResponseCompound {
    pkiEzsigntemplatepackageID:number = 0
    fkiEzsignfoldertypeID:number = 0
    fkiEzdoctemplatedocumentID?:number = undefined
    fkiLanguageID:number = 0
    sEzdoctemplatedocumentNameX?:string = undefined
    sLanguageNameX:string = ''
    sEzsigntemplatepackageDescription:string = ''
    bEzsigntemplatepackageAdminonly:boolean = false
    bEzsigntemplatepackageNeedvalidation:boolean = false
    bEzsigntemplatepackageIsactive:boolean = false
    sEzsignfoldertypeNameX:string = ''
    bEzsigntemplatepackageEditallowed:boolean = false
    a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerResponseCompound> = []
    a_objEzsigntemplatepackagemembership:Array<EzsigntemplatepackagemembershipResponseCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackageResponseCompound Validation Object
 * @class ValidationObjectEzsigntemplatepackageResponseCompound
 */
export class ValidationObjectEzsigntemplatepackageResponseCompound {
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
   fkiEzdoctemplatedocumentID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: false
   }
   fkiLanguageID = {
      type: 'integer',
      minimum: 1,
      maximum: 2,
      required: true
   }
   sEzdoctemplatedocumentNameX = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   sLanguageNameX = {
      type: 'string',
      required: true
   }
   sEzsigntemplatepackageDescription = {
      type: 'string',
      pattern: /^.{0,80}$/,
      required: true
   }
   bEzsigntemplatepackageAdminonly = {
      type: 'boolean',
      required: true
   }
   bEzsigntemplatepackageNeedvalidation = {
      type: 'boolean',
      required: true
   }
   bEzsigntemplatepackageIsactive = {
      type: 'boolean',
      required: true
   }
   sEzsignfoldertypeNameX = {
      type: 'string',
      required: true
   }
   bEzsigntemplatepackageEditallowed = {
      type: 'boolean',
      required: true
   }
   a_objEzsigntemplatepackagesigner = {
      type: 'array',
      required: true
   }
   a_objEzsigntemplatepackagemembership = {
      type: 'array',
      required: true
   }
} 


