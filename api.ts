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


export enum EApiOperation {
    'global-customer-api',
    'global-ezmaxclient-api',
    'global-ezmaxcustomer-api',
    'module-report-api',
    'module-user-api',
    'object-activesession-api',
    'object-apikey-api',
    'object-attachment-api',
    'object-authenticationexternal-api',
    'object-bankaccount-api',
    'object-billingentityexternal-api',
    'object-billingentityinternal-api',
    'object-branding-api',
    'object-buyercontract-api',
    'object-clonehistory-api',
    'object-communication-api',
    'object-company-api',
    'object-contacttitle-api',
    'object-cors-api',
    'object-country-api',
    'object-creditcardclient-api',
    'object-creditcardmerchant-api',
    'object-creditcardtype-api',
    'object-currency-api',
    'object-customer-api',
    'object-department-api',
    'object-discussion-api',
    'object-discussionmembership-api',
    'object-discussionmessage-api',
    'object-domain-api',
    'object-electronicfundstransfer-api',
    'object-emailtype-api',
    'object-ezdoctemplatedocument-api',
    'object-ezdoctemplatefieldtypecategory-api',
    'object-ezdoctemplatetype-api',
    'object-ezmaxcase-api',
    'object-ezmaxinvoicing-api',
    'object-ezmaxproduct-api',
    'object-ezsignannotation-api',
    'object-ezsignbulksend-api',
    'object-ezsignbulksenddocumentmapping-api',
    'object-ezsignbulksendsignermapping-api',
    'object-ezsignbulksendtransmission-api',
    'object-ezsigndiscussion-api',
    'object-ezsigndocument-api',
    'object-ezsignfolder-api',
    'object-ezsignfoldersignerassociation-api',
    'object-ezsignfoldertype-api',
    'object-ezsignformfieldgroup-api',
    'object-ezsignimportdocument-api',
    'object-ezsignimportfolder-api',
    'object-ezsignpage-api',
    'object-ezsignsignature-api',
    'object-ezsignsignergroup-api',
    'object-ezsignsignergroupmembership-api',
    'object-ezsignsigningreason-api',
    'object-ezsigntemplate-api',
    'object-ezsigntemplatedocument-api',
    'object-ezsigntemplatedocumentpagerecognition-api',
    'object-ezsigntemplateformfieldgroup-api',
    'object-ezsigntemplateglobal-api',
    'object-ezsigntemplatepackage-api',
    'object-ezsigntemplatepackagemembership-api',
    'object-ezsigntemplatepackagesigner-api',
    'object-ezsigntemplatepackagesignermembership-api',
    'object-ezsigntemplatepublic-api',
    'object-ezsigntemplatesignature-api',
    'object-ezsigntemplatesigner-api',
    'object-ezsigntsarequirement-api',
    'object-ezsignuser-api',
    'object-font-api',
    'object-franchisebroker-api',
    'object-franchiseoffice-api',
    'object-franchisereferalincome-api',
    'object-glaccount-api',
    'object-glaccountcontainer-api',
    'object-inscription-api',
    'object-inscriptionnotauthenticated-api',
    'object-inscriptiontemp-api',
    'object-invoice-api',
    'object-language-api',
    'object-module-api',
    'object-modulegroup-api',
    'object-notificationsection-api',
    'object-notificationtest-api',
    'object-otherincome-api',
    'object-paymentgateway-api',
    'object-paymentterm-api',
    'object-pdfalevel-api',
    'object-period-api',
    'object-permission-api',
    'object-phonetype-api',
    'object-province-api',
    'object-rejectedoffertopurchase-api',
    'object-secretquestion-api',
    'object-sessionhistory-api',
    'object-signature-api',
    'object-subnet-api',
    'object-supply-api',
    'object-systemconfiguration-api',
    'object-taxassignment-api',
    'object-timezone-api',
    'object-tranqcontract-api',
    'object-user-api',
    'object-usergroup-api',
    'object-usergroupdelegation-api',
    'object-usergroupexternal-api',
    'object-usergroupmembership-api',
    'object-userlogintype-api',
    'object-userstaged-api',
    'object-variableexpense-api',
    'object-versionhistory-api',
    'object-webhook-api',
    'scim-groups-api',
    'scim-service-provider-config-api',
    'scim-users-api'
    
}


export * from './api/global-customer-api';
export * from './api/global-ezmaxclient-api';
export * from './api/global-ezmaxcustomer-api';
export * from './api/module-report-api';
export * from './api/module-user-api';
export * from './api/object-activesession-api';
export * from './api/object-apikey-api';
export * from './api/object-attachment-api';
export * from './api/object-authenticationexternal-api';
export * from './api/object-bankaccount-api';
export * from './api/object-billingentityexternal-api';
export * from './api/object-billingentityinternal-api';
export * from './api/object-branding-api';
export * from './api/object-buyercontract-api';
export * from './api/object-clonehistory-api';
export * from './api/object-communication-api';
export * from './api/object-company-api';
export * from './api/object-contacttitle-api';
export * from './api/object-cors-api';
export * from './api/object-country-api';
export * from './api/object-creditcardclient-api';
export * from './api/object-creditcardmerchant-api';
export * from './api/object-creditcardtype-api';
export * from './api/object-currency-api';
export * from './api/object-customer-api';
export * from './api/object-department-api';
export * from './api/object-discussion-api';
export * from './api/object-discussionmembership-api';
export * from './api/object-discussionmessage-api';
export * from './api/object-domain-api';
export * from './api/object-electronicfundstransfer-api';
export * from './api/object-emailtype-api';
export * from './api/object-ezdoctemplatedocument-api';
export * from './api/object-ezdoctemplatefieldtypecategory-api';
export * from './api/object-ezdoctemplatetype-api';
export * from './api/object-ezmaxcase-api';
export * from './api/object-ezmaxinvoicing-api';
export * from './api/object-ezmaxproduct-api';
export * from './api/object-ezsignannotation-api';
export * from './api/object-ezsignbulksend-api';
export * from './api/object-ezsignbulksenddocumentmapping-api';
export * from './api/object-ezsignbulksendsignermapping-api';
export * from './api/object-ezsignbulksendtransmission-api';
export * from './api/object-ezsigndiscussion-api';
export * from './api/object-ezsigndocument-api';
export * from './api/object-ezsignfolder-api';
export * from './api/object-ezsignfoldersignerassociation-api';
export * from './api/object-ezsignfoldertype-api';
export * from './api/object-ezsignformfieldgroup-api';
export * from './api/object-ezsignimportdocument-api';
export * from './api/object-ezsignimportfolder-api';
export * from './api/object-ezsignpage-api';
export * from './api/object-ezsignsignature-api';
export * from './api/object-ezsignsignergroup-api';
export * from './api/object-ezsignsignergroupmembership-api';
export * from './api/object-ezsignsigningreason-api';
export * from './api/object-ezsigntemplate-api';
export * from './api/object-ezsigntemplatedocument-api';
export * from './api/object-ezsigntemplatedocumentpagerecognition-api';
export * from './api/object-ezsigntemplateformfieldgroup-api';
export * from './api/object-ezsigntemplateglobal-api';
export * from './api/object-ezsigntemplatepackage-api';
export * from './api/object-ezsigntemplatepackagemembership-api';
export * from './api/object-ezsigntemplatepackagesigner-api';
export * from './api/object-ezsigntemplatepackagesignermembership-api';
export * from './api/object-ezsigntemplatepublic-api';
export * from './api/object-ezsigntemplatesignature-api';
export * from './api/object-ezsigntemplatesigner-api';
export * from './api/object-ezsigntsarequirement-api';
export * from './api/object-ezsignuser-api';
export * from './api/object-font-api';
export * from './api/object-franchisebroker-api';
export * from './api/object-franchiseoffice-api';
export * from './api/object-franchisereferalincome-api';
export * from './api/object-glaccount-api';
export * from './api/object-glaccountcontainer-api';
export * from './api/object-inscription-api';
export * from './api/object-inscriptionnotauthenticated-api';
export * from './api/object-inscriptiontemp-api';
export * from './api/object-invoice-api';
export * from './api/object-language-api';
export * from './api/object-module-api';
export * from './api/object-modulegroup-api';
export * from './api/object-notificationsection-api';
export * from './api/object-notificationtest-api';
export * from './api/object-otherincome-api';
export * from './api/object-paymentgateway-api';
export * from './api/object-paymentterm-api';
export * from './api/object-pdfalevel-api';
export * from './api/object-period-api';
export * from './api/object-permission-api';
export * from './api/object-phonetype-api';
export * from './api/object-province-api';
export * from './api/object-rejectedoffertopurchase-api';
export * from './api/object-secretquestion-api';
export * from './api/object-sessionhistory-api';
export * from './api/object-signature-api';
export * from './api/object-subnet-api';
export * from './api/object-supply-api';
export * from './api/object-systemconfiguration-api';
export * from './api/object-taxassignment-api';
export * from './api/object-timezone-api';
export * from './api/object-tranqcontract-api';
export * from './api/object-user-api';
export * from './api/object-usergroup-api';
export * from './api/object-usergroupdelegation-api';
export * from './api/object-usergroupexternal-api';
export * from './api/object-usergroupmembership-api';
export * from './api/object-userlogintype-api';
export * from './api/object-userstaged-api';
export * from './api/object-variableexpense-api';
export * from './api/object-versionhistory-api';
export * from './api/object-webhook-api';
export * from './api/scim-groups-api';
export * from './api/scim-service-provider-config-api';
export * from './api/scim-users-api';

