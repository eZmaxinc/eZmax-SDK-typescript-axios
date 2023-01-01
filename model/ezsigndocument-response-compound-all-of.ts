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
import { CustomEzsignfoldersignerassociationstatusResponse } from './custom-ezsignfoldersignerassociationstatus-response';

import { DefaultObject } from '../base'

/**
 * 
 * @export
 * @interface EzsigndocumentResponseCompoundAllOf
 */
export interface EzsigndocumentResponseCompoundAllOf {
    /**
     * The total number of steps in the form filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepformtotal': number;
    /**
     * The current step in the form filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepformcurrent': number;
    /**
     * The total number of steps in the signature filling phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepsignaturetotal': number;
    /**
     * The current step in the signature phase
     * @type {number}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'iEzsigndocumentStepsignatureCurrent': number;
    /**
     * 
     * @type {Array<CustomEzsignfoldersignerassociationstatusResponse>}
     * @memberof EzsigndocumentResponseCompoundAllOf
     */
    'a_objEzsignfoldersignerassociationstatus': Array<CustomEzsignfoldersignerassociationstatusResponse>;
}
/**
 * A EzsigndocumentResponseCompoundAllOf Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @export 
 * @class DefaultObjectEzsigndocumentResponseCompoundAllOf
 */
export class DefaultObjectEzsigndocumentResponseCompoundAllOf extends DefaultObject {
   iEzsigndocumentStepformtotal:number = 0
   iEzsigndocumentStepformcurrent:number = 0
   iEzsigndocumentStepsignaturetotal:number = 0
   iEzsigndocumentStepsignatureCurrent:number = 0
   a_objEzsignfoldersignerassociationstatus:Array<CustomEzsignfoldersignerassociationstatusResponse> = []
}


